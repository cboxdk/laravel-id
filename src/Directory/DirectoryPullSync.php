<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Enums\DirectorySyncStatus;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Exceptions\DirectorySyncInProgress;
use Cbox\Id\Directory\Hris\Contracts\HrisProvider;
use Cbox\Id\Directory\Hris\HrisDirectorySync;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectorySyncResult;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Throwable;

/**
 * Runs a single API-pull directory sync: fetch the provider's current users, push
 * each through the SAME reconciliation as SCIM ({@see DirectorySync::provisionUser}),
 * then deprovision any user that was present before but is gone from the provider
 * (leavers). Credentials are unsealed per run and never held.
 *
 * The work is wrapped in the directory's OWN environment scope, so it is safe to
 * call from a scheduled command that has no ambient environment pinned.
 *
 * An HR system ({@see HrisProvider}) is handed to {@see HrisDirectorySync}, which knows
 * what employment dates, departments and managers mean and reports per-record failures
 * instead of aborting. Either way the run is bookkept on the directory: when it started,
 * whether it is running, succeeded, partially succeeded or failed, and its counts — and
 * one directory is never synced twice at once (a cache lock, held for the run).
 */
class DirectoryPullSync
{
    public function __construct(
        private readonly DirectoryConnectors $connectors,
        private readonly DirectorySync $sync,
        private readonly DirectoryGroups $groups,
        private readonly SecretBox $secretBox,
        private readonly EnvironmentContext $context,
        private readonly ?HrisDirectorySync $hris = null,
    ) {}

    /**
     * @param  bool  $full  for an HR system that syncs incrementally: ask for everybody this time
     *
     * @throws DirectoryConnectionFailed
     */
    public function sync(Directory $directory, bool $full = false): DirectorySyncResult
    {
        if (! $directory->provider->isPull()) {
            return new DirectorySyncResult(0, 0);
        }

        $environmentId = $directory->getAttribute('environment_id');
        $environmentId = is_string($environmentId) ? $environmentId : '';

        return $this->context->runAs(GenericEnvironment::of($environmentId), function () use ($directory, $full): DirectorySyncResult {
            $lock = Cache::lock('cbox-id:directory-sync:'.$directory->id, $this->lockSeconds());

            if (! $lock->get()) {
                throw DirectorySyncInProgress::for($directory->id);
            }

            $startedAt = Carbon::now();

            try {
                $directory->forceFill([
                    'last_sync_started_at' => $startedAt,
                    'last_sync_status' => DirectorySyncStatus::Running,
                ])->save();

                return $this->run($directory, $full, $startedAt);
            } finally {
                $lock->release();
            }
        });
    }

    private function run(Directory $directory, bool $full, Carbon $startedAt): DirectorySyncResult
    {
        try {
            $connector = $this->connectors->for($directory->provider);
            $credentials = $this->credentials($directory);

            $result = $connector instanceof HrisProvider
                ? $this->hris()->sync($directory, $connector, $credentials, $full)
                : $this->pull($directory, $connector, $credentials);

            $bookkeeping = [
                'last_synced_at' => now(),
                'last_sync_error' => $result->partial() ? $this->summary($result) : null,
                'last_sync_status' => $result->partial() ? DirectorySyncStatus::Partial : DirectorySyncStatus::Succeeded,
                'last_sync_stats' => $result->toArray(),
            ];

            if ($connector instanceof HrisProvider) {
                // The next incremental run asks for what changed since THIS one started.
                $bookkeeping['sync_cursor'] = $connector->supportsIncremental() ? $startedAt->toIso8601String() : null;

                if (! $result->incremental) {
                    $bookkeeping['last_full_sync_at'] = $startedAt;
                }
            }

            $directory->forceFill($bookkeeping)->save();

            return $result;
        } catch (DirectoryConnectionFailed $e) {
            // Record the reason (no credentials) so an admin can see the failure.
            $directory->forceFill([
                'last_sync_error' => $e->getMessage(),
                'last_sync_status' => DirectorySyncStatus::Failed,
            ])->save();

            throw $e;
        } catch (Throwable $e) {
            // Not a connection failure — a bug or a database error. Still recorded, so the
            // directory does not read "running" forever; the message stays out of the
            // record because it is nobody's business what a stack trace said.
            $directory->forceFill([
                'last_sync_error' => 'Directory sync failed unexpectedly ('.class_basename($e).').',
                'last_sync_status' => DirectorySyncStatus::Failed,
            ])->save();

            throw $e;
        }
    }

    /**
     * The identity-directory pull: everybody the provider returns, provisioned; everybody
     * it did not, deprovisioned; then the groups.
     *
     * @param  array<string, mixed>  $credentials
     */
    private function pull(Directory $directory, DirectoryConnector $connector, array $credentials): DirectorySyncResult
    {
        $seen = [];
        $provisioned = 0;

        foreach ($connector->fetchUsers($credentials) as $scimUser) {
            $this->sync->provisionUser($directory->id, $scimUser);
            $seen[$scimUser->externalId] = true;
            $provisioned++;
        }

        $deprovisioned = $this->deprovisionMissing($directory, $seen);
        $groupsSynced = $this->syncGroups($directory, $connector, $credentials);

        return new DirectorySyncResult($provisioned, $deprovisioned, $groupsSynced);
    }

    private function hris(): HrisDirectorySync
    {
        return $this->hris ?? app(HrisDirectorySync::class);
    }

    /** One line for `last_sync_error` when a run partly failed: the count and the first reason. */
    private function summary(DirectorySyncResult $result): string
    {
        $first = $result->failures[0] ?? null;
        $line = $result->failed === 1 ? '1 record could not be synced' : "{$result->failed} records could not be synced";

        if ($first === null) {
            return $line.'.';
        }

        return $line.($first->externalId === null ? '' : " (first: {$first->externalId})").': '.$first->reason;
    }

    /** How long the per-directory lock is held at most — longer than any sane run. */
    private function lockSeconds(): int
    {
        $seconds = config('cbox-id.directory.lock_seconds', 3600);

        return is_numeric($seconds) ? max(60, (int) $seconds) : 3600;
    }

    /**
     * Reconcile the provider's groups into DirectoryGroups (same store SCIM Groups
     * use, so group→role mappings apply identically). Members are resolved from
     * provider external ids to our directory-user ids; unknown members are skipped.
     *
     * @param  array<string, mixed>  $credentials
     */
    private function syncGroups(Directory $directory, DirectoryConnector $connector, array $credentials): int
    {
        $userIdByExternal = [];

        DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->get(['id', 'external_id'])
            ->each(function (DirectoryUser $user) use (&$userIdByExternal): void {
                $external = $user->getAttribute('external_id');

                if (is_string($external)) {
                    $userIdByExternal[$external] = $user->id;
                }
            });

        $count = 0;

        foreach ($connector->fetchGroups($credentials) as $snapshot) {
            $memberIds = [];

            foreach ($snapshot->memberExternalIds as $external) {
                if (isset($userIdByExternal[$external])) {
                    $memberIds[] = $userIdByExternal[$external];
                }
            }

            $existing = DirectoryGroup::query()
                ->where('directory_id', $directory->id)
                ->where('external_id', $snapshot->externalId)
                ->first();

            if ($existing !== null) {
                $this->groups->replace($existing, $snapshot->displayName, $snapshot->externalId, $memberIds);
            } else {
                $this->groups->create($directory, $snapshot->displayName, $snapshot->externalId, $memberIds);
            }

            $count++;
        }

        return $count;
    }

    /**
     * @param  array<string, true>  $seen
     */
    private function deprovisionMissing(Directory $directory, array $seen): int
    {
        $count = 0;

        DirectoryUser::query()
            ->where('directory_id', $directory->id)
            ->where('active', true)
            ->each(function (DirectoryUser $user) use ($directory, $seen, &$count): void {
                $externalId = $user->getAttribute('external_id');

                if (is_string($externalId) && ! isset($seen[$externalId])) {
                    $this->sync->deprovisionUser($directory->id, $externalId);
                    $count++;
                }
            });

        return $count;
    }

    /**
     * @return array<string, mixed>
     */
    private function credentials(Directory $directory): array
    {
        if ($directory->credentials === null) {
            throw DirectoryConnectionFailed::make($directory->provider->value, 'No credentials are configured for this directory.');
        }

        $json = $this->secretBox->open($directory->credentials, $this->context($directory->id));
        $decoded = json_decode($json, true);

        if (! is_array($decoded)) {
            return [];
        }

        $credentials = [];

        foreach ($decoded as $key => $value) {
            if (is_string($key)) {
                $credentials[$key] = $value;
            }
        }

        return $credentials;
    }

    private function context(string $directoryId): string
    {
        return 'cbox-id:directory-credentials:'.$directoryId;
    }
}
