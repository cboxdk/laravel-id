<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectorySyncResult;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;

/**
 * Runs a single API-pull directory sync: fetch the provider's current users, push
 * each through the SAME reconciliation as SCIM ({@see DirectorySync::provisionUser}),
 * then deprovision any user that was present before but is gone from the provider
 * (leavers). Credentials are unsealed per run and never held.
 *
 * The work is wrapped in the directory's OWN environment scope, so it is safe to
 * call from a scheduled command that has no ambient environment pinned.
 */
class DirectoryPullSync
{
    public function __construct(
        private readonly DirectoryConnectors $connectors,
        private readonly DirectorySync $sync,
        private readonly DirectoryGroups $groups,
        private readonly SecretBox $secretBox,
        private readonly EnvironmentContext $context,
    ) {}

    public function sync(Directory $directory): DirectorySyncResult
    {
        if (! $directory->provider->isPull()) {
            return new DirectorySyncResult(0, 0);
        }

        $environmentId = $directory->getAttribute('environment_id');
        $environmentId = is_string($environmentId) ? $environmentId : '';

        return $this->context->runAs(GenericEnvironment::of($environmentId), function () use ($directory): DirectorySyncResult {
            $connector = $this->connectors->for($directory->provider);
            $credentials = $this->credentials($directory);

            try {
                $seen = [];
                $provisioned = 0;

                foreach ($connector->fetchUsers($credentials) as $scimUser) {
                    $this->sync->provisionUser($directory->id, $scimUser);
                    $seen[$scimUser->externalId] = true;
                    $provisioned++;
                }

                $deprovisioned = $this->deprovisionMissing($directory, $seen);
                $groupsSynced = $this->syncGroups($directory, $connector, $credentials);

                $directory->forceFill(['last_synced_at' => now(), 'last_sync_error' => null])->save();

                return new DirectorySyncResult($provisioned, $deprovisioned, $groupsSynced);
            } catch (DirectoryConnectionFailed $e) {
                // Record the reason (no credentials) so an admin can see the failure.
                $directory->forceFill(['last_sync_error' => $e->getMessage()])->save();

                throw $e;
            }
        });
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
