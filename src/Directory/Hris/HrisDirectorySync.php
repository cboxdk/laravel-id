<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris;

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Exceptions\DirectoryGroupNameTaken;
use Cbox\Id\Directory\Exceptions\DirectoryUserNameTaken;
use Cbox\Id\Directory\Hris\Contracts\HrisProvider;
use Cbox\Id\Directory\Hris\Support\HrisValues;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectorySyncResult;
use Cbox\Id\Directory\ValueObjects\SyncFailure;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\Scim\ScimSchema;
use Throwable;

/**
 * One HR-system pull: employees into directory users, departments into groups, leavers out.
 *
 * Run by {@see DirectoryPullSync} — inside the directory's own
 * environment, with the credentials already unsealed, holding the directory's sync lock —
 * whenever the connector is an {@see HrisProvider}. Every write goes through the same
 * {@see DirectorySync} reconciliation a SCIM push uses, so sessions are revoked, memberships
 * dropped and audit entries written exactly as they are for an identity provider.
 *
 * **What differs from an identity directory**, and why:
 *
 * - **A leaver who never had an account gets none.** An HR system reports every person it
 *   ever employed; provisioning ten years of former staff as deactivated accounts would be
 *   a data-protection problem of our own making. Inactive, terminated and not-yet-started
 *   people are only written when they are ALREADY in the directory (to deactivate them).
 * - **One bad record costs one record.** An email that belongs to an unlinked account, or a
 *   person with no work email, is a {@see SyncFailure} on the run — reported, not thrown —
 *   and the person is still counted as seen, so a data-quality problem never deprovisions
 *   somebody who is still employed.
 * - **Incremental when the provider can.** A provider that answers "changed since" is asked
 *   that, between full pulls at most `cbox-id.directory.hris.full_sync_hours` apart; an
 *   incremental run deprovisions nobody for being absent, because absent means unchanged.
 * - **Termination dates are swept every run**, from what is stored, so a leaver whose
 *   record did not change on their last day still loses access when the day ends.
 * - **A mass deprovisioning is refused.** A full pull that would deactivate more than
 *   `cbox-id.directory.hris.deprovision_guard` of the active people (an API key that lost
 *   access to most departments looks exactly like a mass layoff) deprovisions nobody and
 *   reports why. Set the guard to `1` to turn it off.
 * - **Departments become groups** with the external id `department:{id}`, rebuilt from the
 *   stored people every run so incremental runs keep membership right, and removed when
 *   the department is gone and empty.
 */
final class HrisDirectorySync
{
    /** Group external ids for departments start with this, so nothing else is touched. */
    public const string DEPARTMENT_PREFIX = 'department:';

    /** How far an incremental cursor is wound back, against clock skew between us and them. */
    private const int CURSOR_OVERLAP_MINUTES = 5;

    private int $failed = 0;

    /** @var list<SyncFailure> */
    private array $failures = [];

    public function __construct(
        private readonly DirectorySync $sync,
        private readonly DirectoryGroups $groups,
    ) {}

    /**
     * @param  array<string, mixed>  $credentials
     *
     * @throws DirectoryConnectionFailed
     */
    public function sync(Directory $directory, HrisProvider $provider, array $credentials, bool $full = false): DirectorySyncResult
    {
        $this->failed = 0;
        $this->failures = [];

        $mapper = HrisEmployeeMapper::fromConfig();
        $options = HrisSyncOptions::fromMappings($directory->mappings ?? []);
        $since = $full ? null : $this->changedSince($directory, $provider);
        $options = $options->withChangedSince($since);

        // Departments FIRST: a provider that refuses them fails the run before any person
        // has been written, rather than after.
        $departmentNames = [];

        foreach ($provider->fetchDepartments($credentials, $options) as $department) {
            $departmentNames[$department->id] = $department->name;
        }

        /** @var array<string, bool> $known external id => active */
        $known = [];

        DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->get(['external_id', 'active'])
            ->each(function (DirectoryUser $user) use (&$known): void {
                $known[$user->external_id] = (bool) $user->active;
            });

        $seen = [];
        $provisioned = 0;
        $deprovisioned = 0;
        $skipped = 0;

        foreach ($provider->fetchEmployees($credentials, $options) as $employee) {
            // Seen whatever happens next: a record we could not reconcile is still a person
            // the HR system says exists, and must not be deprovisioned for our failure.
            $seen[$employee->id] = true;

            $scim = $mapper->toScimUser($employee, $directory->provider);
            $isKnown = array_key_exists($employee->id, $known);
            $wasActive = $known[$employee->id] ?? false;

            try {
                if ($scim === null) {
                    if ($mapper->grantsAccess($employee)) {
                        $this->fail($employee->id, 'Has no work email in the HR system, so no account can be made for them.');
                    } elseif ($wasActive) {
                        $this->sync->deprovisionUser($directory->id, $employee->id);
                        $deprovisioned++;
                    } else {
                        $skipped++;
                    }

                    continue;
                }

                if (! $scim->active && ! $isKnown) {
                    // A leaver, or somebody who has not started: nobody to deactivate.
                    $skipped++;

                    continue;
                }

                $this->sync->provisionUser($directory->id, $scim);

                if ($scim->active) {
                    $provisioned++;
                } elseif ($wasActive) {
                    $deprovisioned++;
                } else {
                    $skipped++;
                }
            } catch (DirectoryConnectionFailed $e) {
                throw $e;
            } catch (Throwable $e) {
                $this->fail($employee->id, $this->reason($e));
            }
        }

        $deprovisioned += $this->sweepTerminations($directory, $seen);

        if ($since === null) {
            $deprovisioned += $this->deprovisionMissing($directory, $seen);
        }

        $groups = $this->syncDepartments($directory, $departmentNames);

        return new DirectorySyncResult(
            provisioned: $provisioned,
            deprovisioned: $deprovisioned,
            groupsSynced: $groups,
            skipped: $skipped,
            failed: $this->failed,
            failures: $this->failures,
            incremental: $since !== null,
        );
    }

    /**
     * The instant to ask "changed since", or null for a full pull.
     */
    private function changedSince(Directory $directory, HrisProvider $provider): ?CarbonImmutable
    {
        if (! $provider->supportsIncremental() || $directory->sync_cursor === null || $directory->last_full_sync_at === null) {
            return null;
        }

        $hours = config('cbox-id.directory.hris.full_sync_hours', 24);
        $hours = is_numeric($hours) ? max(1, (int) $hours) : 24;

        if ($directory->last_full_sync_at->lte(now()->subHours($hours))) {
            return null;
        }

        try {
            return CarbonImmutable::parse($directory->sync_cursor)->subMinutes(self::CURSOR_OVERLAP_MINUTES);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Deactivate everybody stored as active whose termination date has passed and who was
     * not already reconciled from a fresh record this run.
     *
     * @param  array<string, true>  $seen
     */
    private function sweepTerminations(Directory $directory, array $seen): int
    {
        $count = 0;
        $today = CarbonImmutable::now();

        DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->where('active', true)
            ->each(function (DirectoryUser $user) use ($directory, $seen, $today, &$count): void {
                if (isset($seen[$user->external_id])) {
                    return;
                }

                $resource = $user->resource;
                $ends = HrisValues::date($resource, HrisEmployeeMapper::SCHEMA, 'terminationDate');

                if ($ends !== null && $ends->endOfDay()->lt($today)) {
                    try {
                        $this->sync->deprovisionUser($directory->id, $user->external_id);
                        $count++;
                    } catch (Throwable $e) {
                        $this->fail($user->external_id, $this->reason($e));
                    }
                }
            });

        return $count;
    }

    /**
     * Deprovision the active people a FULL pull did not return — unless that is so many of
     * them that it is more likely an API key that lost its reach than a company that lost
     * its staff.
     *
     * @param  array<string, true>  $seen
     */
    private function deprovisionMissing(Directory $directory, array $seen): int
    {
        $active = DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->where('active', true)
            ->pluck('external_id')
            ->all();

        $missing = array_values(array_filter($active, static fn (mixed $id): bool => is_string($id) && ! isset($seen[$id])));

        if ($missing === []) {
            return 0;
        }

        $guard = config('cbox-id.directory.hris.deprovision_guard', 0.5);
        $guard = is_numeric($guard) ? (float) $guard : 0.5;

        if ($guard < 1.0 && count($active) >= 10 && count($missing) / count($active) > $guard) {
            $this->fail(null, sprintf(
                'Refused to deprovision %d of %d active people who were missing from the HR system\'s answer — more than %d%%. Check the integration\'s permissions; run a full sync once the HR system returns everybody again.',
                count($missing),
                count($active),
                (int) round($guard * 100),
            ));

            return 0;
        }

        $count = 0;

        foreach ($missing as $externalId) {
            try {
                $this->sync->deprovisionUser($directory->id, $externalId);
                $count++;
            } catch (Throwable $e) {
                $this->fail($externalId, $this->reason($e));
            }
        }

        return $count;
    }

    /**
     * Departments as groups, membership from the stored ACTIVE people.
     *
     * @param  array<string, string>  $names  department id => name, from the provider
     */
    private function syncDepartments(Directory $directory, array $names): int
    {
        /** @var array<string, list<string>> $members department key => directory-user ids */
        $members = [];

        DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->where('active', true)
            ->each(function (DirectoryUser $user) use (&$members, &$names): void {
                $resource = $user->resource;
                $key = HrisValues::string($resource, HrisEmployeeMapper::SCHEMA, 'departmentId');

                if ($key === null) {
                    return;
                }

                $members[$key][] = $user->id;

                $name = HrisValues::string($resource, ScimSchema::ENTERPRISE_URN, 'department');

                if (! isset($names[$key]) && $name !== null) {
                    $names[$key] = $name;
                }
            });

        // Every department we know a name for, with or without people in it yet — so a role
        // can be mapped to a department before anybody joins it.
        $keys = array_values(array_unique([...array_map('strval', array_keys($names)), ...array_map('strval', array_keys($members))]));
        $display = $this->displayNames($keys, $names);

        $existing = DirectoryGroup::query()
            ->where('directory_id', $directory->id)
            ->where('external_id', 'like', self::DEPARTMENT_PREFIX.'%')
            ->with('members:id')
            ->get()
            ->keyBy('external_id');

        $count = 0;

        foreach ($keys as $key) {
            $externalId = self::DEPARTMENT_PREFIX.$key;
            $memberIds = $members[$key] ?? [];
            sort($memberIds);

            try {
                $group = $existing->get($externalId);

                if ($group instanceof DirectoryGroup) {
                    $current = $group->members->pluck('id')->map(static fn (mixed $id): string => is_string($id) ? $id : '')->sort()->values()->all();

                    if ($group->display_name !== $display[$key] || $current !== $memberIds) {
                        $this->groups->replace($group, $display[$key], $externalId, $memberIds);
                    }
                } else {
                    $this->groups->create($directory, $display[$key], $externalId, $memberIds);
                }

                $count++;
            } catch (DirectoryGroupNameTaken) {
                $this->fail(null, "The department \"{$display[$key]}\" could not be filed as a group: another group in this directory already has that name.");
            }
        }

        // A department the HR system no longer has, and nobody is filed under, is gone.
        foreach ($existing as $externalId => $group) {
            $key = substr((string) $externalId, strlen(self::DEPARTMENT_PREFIX));

            if (! in_array($key, $keys, true)) {
                $this->groups->delete($group);
            }
        }

        return $count;
    }

    /**
     * A group name per department, unique within the directory: two departments called
     * "Sales" in two divisions are both kept, each with its id beside the name.
     *
     * @param  list<string>  $keys
     * @param  array<string, string>  $names
     * @return array<string, string>
     */
    private function displayNames(array $keys, array $names): array
    {
        $byName = [];

        foreach ($keys as $key) {
            $name = $names[$key] ?? (str_starts_with($key, 'name:') ? substr($key, 5) : $key);
            $byName[mb_strtolower($name)][] = $key;
            $names[$key] = $name;
        }

        $display = [];

        foreach ($keys as $key) {
            $name = $names[$key];
            $display[$key] = count($byName[mb_strtolower($name)]) > 1 ? "{$name} ({$key})" : $name;
        }

        return $display;
    }

    private function fail(?string $externalId, string $reason): void
    {
        $this->failed++;

        $limit = config('cbox-id.directory.hris.max_reported_failures', 50);
        $limit = is_numeric($limit) ? max(0, (int) $limit) : 50;

        if (count($this->failures) < $limit) {
            $this->failures[] = new SyncFailure($externalId, $reason);
        }
    }

    /**
     * Why a record could not be reconciled, in words that carry no personal data — the
     * exceptions' own messages can name the email address.
     */
    private function reason(Throwable $e): string
    {
        return match (true) {
            $e instanceof AccountExistsForEmail => 'Their work email belongs to an existing account that is not linked to this directory. Link or remove that account, then sync again.',
            $e instanceof DirectoryUserNameTaken => 'Another employee in this directory has the same work email.',
            default => $this->unexpected($e),
        };
    }

    private function unexpected(Throwable $e): string
    {
        report($e);

        return 'Could not be provisioned ('.class_basename($e).').';
    }
}
