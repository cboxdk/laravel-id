<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\ClientType;

readonly class NewClient
{
    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $postLogoutRedirectUris  URIs allowed after RP-initiated logout (OIDC RP-Initiated Logout 1.0)
     * @param  list<string>  $grantTypes
     * @param  list<string>  $scopes
     * @param  array<string, mixed>|null  $jwks  a public JWK Set (RFC 7517) for `private_key_jwt` auth; null = secret/`none`
     */
    public function __construct(
        public string $name,
        public ClientType $type = ClientType::Confidential,
        public array $redirectUris = [],
        public array $grantTypes = ['client_credentials'],
        public array $scopes = [],
        public bool $firstParty = false,
        public ?string $organizationId = null,
        public ?array $jwks = null,
        public array $postLogoutRedirectUris = [],

        /**
         * This client's access-token lifetime in seconds, or null for the deployment
         * default. Set it when the client's revocation story differs from the platform's
         * — a credential a resource server validates offline can only be revoked by
         * expiry, so its TTL is its revocation window.
         */
        public ?int $accessTokenTtl = null,
    ) {}
}
