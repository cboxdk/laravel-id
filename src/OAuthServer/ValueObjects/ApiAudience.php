<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * A registered API as the token issuer sees it: the audience a token can be bound to,
 * who owns it, and whose RBAC a token for it carries. Detached from Eloquent so the
 * issuance path reads a value, not a live row.
 */
readonly class ApiAudience
{
    public function __construct(
        public string $id,
        /** The absolute URI stamped into `aud`. */
        public string $identifier,
        /** The owning organization; null = environment-owned. */
        public ?string $organizationId = null,
        /** The app whose declared roles/permissions the API enforces; null = none linked. */
        public ?string $clientId = null,
    ) {}

    public function isEnvironmentOwned(): bool
    {
        return $this->organizationId === null;
    }
}
