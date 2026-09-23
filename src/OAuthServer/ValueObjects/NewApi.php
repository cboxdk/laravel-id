<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

/**
 * An API to register in the current environment.
 */
readonly class NewApi
{
    /**
     * @param  list<ApiScopeDefinition>  $scopes
     */
    public function __construct(
        /** Absolute URI (RFC 8707 resource indicator), no fragment. Becomes `aud`. */
        public string $identifier,
        public string $name,
        /** The owning organization; null = environment-owned. */
        public ?string $organizationId = null,
        /** The app whose declared roles/permissions this API enforces. */
        public ?string $clientId = null,
        public array $scopes = [],
    ) {}
}
