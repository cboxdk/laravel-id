<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * A scope some registered API owns, with the API it belongs to.
 */
readonly class RegisteredScope
{
    public function __construct(
        public string $key,
        public ApiAudience $api,
        public bool $tenantRequestable = true,
        public ?string $description = null,
    ) {}

    /**
     * THE OWNERSHIP RULE, in the one place it is written.
     *
     * A client may hold a registered scope when:
     *  - the client is environment-owned (the operators' own apps hold anything), or
     *  - the client belongs to the organization that owns the API, or
     *  - the API is environment-owned AND the scope is marked tenant-requestable.
     *
     * Everything else is refused — in particular a tenant's client can never hold a scope
     * of another tenant's API, and never a scope the environment kept for itself.
     * Registration and issuance both ask this, so a row written before the API existed
     * (or by a writer that skipped the registry) is still refused at the token endpoint.
     */
    public function mayBeHeldBy(ScopeHolder $holder): bool
    {
        if ($holder->isEnvironmentOwned()) {
            return true;
        }

        if ($this->api->organizationId !== null) {
            return $holder->organizationId === $this->api->organizationId;
        }

        return $this->tenantRequestable;
    }
}
