<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * A scope an API declares. `tenantRequestable` defaults to true: a scope on an
 * environment-owned API is offered to organization-owned (and dynamically registered)
 * clients unless the API keeps it for the environment's own apps.
 */
readonly class ApiScopeDefinition
{
    public function __construct(
        public string $key,
        public ?string $description = null,
        public bool $tenantRequestable = true,
    ) {}
}
