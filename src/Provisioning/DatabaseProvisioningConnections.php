<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Provisioning\Contracts\ProvisioningConnections;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Enums\ConnectionStatus;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\Support\SafeScimUrl;
use Cbox\Id\Provisioning\ValueObjects\RegisteredConnection;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

final class DatabaseProvisioningConnections implements ProvisioningConnections
{
    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly Memberships $memberships,
    ) {}

    public function register(
        ?string $organizationId,
        string $name,
        string $baseUrl,
        AuthScheme $authScheme,
        string $secret,
        array $attributeMapping = [],
        array $organizationIds = [],
        DeprovisionPolicy $deprovisionPolicy = DeprovisionPolicy::Deactivate,
        array $authConfig = [],
    ): RegisteredConnection {
        // SSRF guard: refuse a target that points at a non-public address.
        SafeScimUrl::assert($baseUrl);

        $connection = new ProvisioningConnection;
        $connection->id = (string) Str::ulid();
        $connection->fill([
            'organization_id' => $organizationId,
            'name' => $name,
            'base_url' => $baseUrl,
            'auth_scheme' => $authScheme,
            'auth_config' => $authConfig,
            'attribute_mapping' => $attributeMapping,
            'scope' => ['organization_ids' => $organizationIds],
            'deprovision_policy' => $deprovisionPolicy,
            'status' => ConnectionStatus::Active,
            'consecutive_failures' => 0,
        ]);
        // Sealed at rest, bound to this connection's id; never returned again.
        $connection->auth_secret_encrypted = $this->secretBox->seal($secret, $connection->secretContext());
        $connection->save();

        return new RegisteredConnection($connection);
    }

    public function pause(string $connectionId): void
    {
        ProvisioningConnection::query()->whereKey($connectionId)->first()
            ?->update(['status' => ConnectionStatus::Paused]);
    }

    /**
     * @return Collection<int, ProvisioningConnection>
     */
    public function active(): Collection
    {
        return ProvisioningConnection::query()
            ->where('status', ConnectionStatus::Active->value)
            ->get();
    }

    public function inScopeFor(string $userId, ?string $organizationId): Collection
    {
        $connections = $this->active();

        if ($connections->isEmpty()) {
            return $connections;
        }

        // Resolve the subject's organizations lazily — only needed to place a
        // user-level change (no org on the event) against an org-scoped connection.
        $userOrgIds = null;

        return $connections->filter(function (ProvisioningConnection $connection) use ($userId, $organizationId, &$userOrgIds): bool {
            if ($connection->isEnvironmentWide()) {
                return true;
            }

            $scopeOrgIds = $connection->scopeOrganizationIds();

            if ($organizationId !== null) {
                return in_array($organizationId, $scopeOrgIds, true);
            }

            $userOrgIds ??= $this->userOrganizationIds($userId);

            return array_intersect($scopeOrgIds, $userOrgIds) !== [];
        })->values();
    }

    public function leftScopeFor(string $userId, ?string $removedOrganizationId): Collection
    {
        $connections = $this->active();

        if ($connections->isEmpty()) {
            return $connections;
        }

        // The user's memberships AFTER the removal — a remaining membership in any
        // of a connection's orgs means the user is still entitled there.
        $currentOrgIds = $this->userOrganizationIds($userId);

        return $connections->filter(function (ProvisioningConnection $connection) use ($removedOrganizationId, $currentOrgIds): bool {
            // An org removal never removes the user from the ENVIRONMENT, so an
            // environment-wide connection still covers them — never deprovision here.
            if ($connection->isEnvironmentWide()) {
                return false;
            }

            $scopeOrgIds = $connection->scopeOrganizationIds();

            // Only a connection that actually covered the removed org is a candidate
            // (so an unrelated connection never gets a no-op deprovision).
            if ($removedOrganizationId !== null && ! in_array($removedOrganizationId, $scopeOrgIds, true)) {
                return false;
            }

            // Deprovision ONLY when no remaining membership keeps the user in scope.
            return array_intersect($scopeOrgIds, $currentOrgIds) === [];
        })->values();
    }

    /**
     * The organizations a subject belongs to in the current environment.
     *
     * @return list<string>
     */
    private function userOrganizationIds(string $userId): array
    {
        $ids = [];

        foreach ($this->memberships->forUser($userId) as $membership) {
            $organizationId = $membership->getAttribute('organization_id');

            if (is_string($organizationId)) {
                $ids[] = $organizationId;
            }
        }

        return $ids;
    }
}
