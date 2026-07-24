<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\DynamicClientRegistrar;

/**
 * The validated, normalized client metadata from an RFC 7591 registration
 * request. Construction is via {@see DynamicClientRegistrar}
 * which enforces the policy (allowed grant types/scopes, redirect-uri rules); this
 * object only carries the already-vetted result.
 */
readonly class ClientMetadata
{
    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $grantTypes
     * @param  list<string>  $responseTypes
     * @param  list<string>  $scopes
     */
    public function __construct(
        public string $clientName,
        public string $tokenEndpointAuthMethod,
        public array $redirectUris,
        public array $grantTypes,
        public array $responseTypes,
        public array $scopes,
    ) {}

    /**
     * `none` is the RFC 7591 auth method for public clients (PKCE-only). Anything
     * else means the client holds a secret.
     */
    public function isPublic(): bool
    {
        return $this->tokenEndpointAuthMethod === 'none';
    }
}
