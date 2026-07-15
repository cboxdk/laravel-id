<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Contracts;

use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\ValueObjects\RegisteredConnection;
use Illuminate\Support\Collection;

/**
 * The registry of downstream provisioning targets in the current environment.
 * All reads are environment-scoped by the hard scope, so a connection registered
 * in one environment is invisible to another.
 */
interface ProvisioningConnections
{
    /**
     * Register a downstream SCIM target. The `$secret` (bearer token or OAuth
     * client secret) is sealed at rest and never returned again; the base URL is
     * SSRF-checked before it is stored.
     *
     * @param  list<string>  $organizationIds  empty ⇒ environment-wide
     * @param  array<string, mixed>  $attributeMapping  scimPath => sourceKey
     * @param  array<string, mixed>  $authConfig  scheme extras (OAuth token_url, client_id, scope)
     */
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
    ): RegisteredConnection;

    public function pause(string $connectionId): void;

    /**
     * Every active connection in the current environment.
     *
     * @return Collection<int, ProvisioningConnection>
     */
    public function active(): Collection;

    /**
     * The active connections in the current environment that are in scope for a
     * change to `$userId` (optionally within `$organizationId`) — the exact set to
     * enqueue an operation for. Deny-by-default: none configured ⇒ empty.
     *
     * @return Collection<int, ProvisioningConnection>
     */
    public function inScopeFor(string $userId, ?string $organizationId): Collection;

    /**
     * The active connections a user has now LEFT, for a membership-removal
     * deprovision. Critically NARROWER than the negation of {@see inScopeFor()}: an
     * organization removal deprovisions only an ORG-SCOPED connection that (a)
     * covered the user via the removed org and (b) no longer covers them by ANY
     * remaining membership. An ENVIRONMENT-WIDE connection is never returned — an
     * org removal does not remove the user from the environment, so they are still
     * entitled there. This is what stops a `member_removed` from deactivating or
     * DELETing a user who is still a member of another org the same connection
     * provisions.
     *
     * @return Collection<int, ProvisioningConnection>
     */
    public function leftScopeFor(string $userId, ?string $removedOrganizationId): Collection;
}
