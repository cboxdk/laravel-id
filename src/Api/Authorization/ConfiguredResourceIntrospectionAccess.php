<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Authorization;

use Cbox\Id\Api\Contracts\ResourceIntrospectionAccess;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;

/** Explicit host grants; API-to-app RBAC linkage alone grants no introspection access. */
class ConfiguredResourceIntrospectionAccess implements ResourceIntrospectionAccess
{
    public function __construct(
        private readonly IssuerResolver $issuers,
        private readonly Organizations $organizations,
        private readonly Memberships $memberships,
    ) {}

    public function allows(Client $caller, Introspection $token): bool
    {
        if (! $token->active) {
            return false;
        }

        $grants = config('cbox-id.oauth.introspection.resource_servers', []);
        $allowed = is_array($grants) ? ($grants[$caller->client_id] ?? []) : [];
        $audience = $token->claims['aud'] ?? null;
        // Resource tokens issued here have exactly one audience. Do not widen a
        // malformed or multi-audience token into a cross-client grant.
        if (! is_array($allowed) || ! is_string($audience) || $audience === ''
            || $audience === $this->issuers->issuer()
            || ! in_array($audience, $allowed, true)) {
            return false;
        }

        $org = $token->claims['org'] ?? null;
        if ($caller->organization_id !== null && $org !== $caller->organization_id) {
            return false;
        }

        if ($org === null) {
            return true;
        }
        if (! is_string($org) || $org === '') {
            return false;
        }

        $organization = $this->organizations->find($org);
        if ($organization === null || $organization->status->revokesAccess()) {
            return false;
        }

        // A resource-server lookup is a current access decision, not merely a
        // historical token check. Machine subjects have no user membership.
        return $token->subject !== null && ($token->subject === $token->clientId
            || $this->memberships->activeRole($org, $token->subject) !== null);
    }
}
