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
     * @param  array<string, mixed>|null  $jwks  the client's public JWK Set, for
     *                                           `private_key_jwt` — null for every other method
     */
    public function __construct(
        public string $clientName,
        public string $tokenEndpointAuthMethod,
        public array $redirectUris,
        public array $grantTypes,
        public array $responseTypes,
        public array $scopes,
        public ?array $jwks = null,
    ) {}

    /**
     * `none` is the RFC 7591 auth method for public clients (PKCE-only). Anything
     * else means the client holds a credential — a shared secret, or the private half
     * of {@see self::$jwks}.
     */
    public function isPublic(): bool
    {
        return $this->tokenEndpointAuthMethod === 'none';
    }

    /**
     * Whether this client proves itself by signing an assertion rather than by presenting
     * a shared secret.
     *
     * Asked as its own question because the two are exclusive: the registry issues no
     * secret to a client that registered keys, so a caller that treats "confidential" as
     * "has a secret" gets a client it cannot authenticate.
     */
    public function usesPrivateKeyJwt(): bool
    {
        return $this->tokenEndpointAuthMethod === 'private_key_jwt';
    }
}
