<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Support\BackchannelLogoutUri;
use Cbox\Id\OAuthServer\Support\ClientSettingsRules;
use Cbox\Id\Organization\ValueObjects\ApiKeyPrefix;

readonly class NewClient
{
    /**
     * @param  list<string>  $redirectUris
     * @param  list<string>  $postLogoutRedirectUris  URIs allowed after RP-initiated logout (OIDC RP-Initiated Logout 1.0)
     * @param  list<string>  $grantTypes  each a {@see GrantType} value; token exchange needs a confidential client
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

        /**
         * How the client authenticates at the token endpoint (RFC 7591), recorded rather
         * than inferred. Null leaves it to be inferred from the type and key set, as
         * before. Must agree with both — see {@see ClientSettingsRules::assertAuthMethod()}.
         */
        public ?TokenEndpointAuthMethod $tokenEndpointAuthMethod = null,

        /** Where the app publishes its roles-and-permissions manifest (the pull transport). */
        public ?string $manifestUrl = null,

        /**
         * Where to POST a logout token when a session that signed a person in to this
         * client ends (OIDC Back-Channel Logout 1.0). Null = the client is never told.
         * HTTPS, or HTTP on localhost — see {@see BackchannelLogoutUri}.
         */
        public ?string $backchannelLogoutUri = null,

        /** Whether every logout token sent to this client must carry `sid` (§2.2). */
        public bool $backchannelLogoutSessionRequired = false,

        /**
         * The prefix of this app's customer API keys (`acme_live`), or null for an app that
         * accepts none. Unique per environment — see {@see ApiKeyPrefix}.
         */
        public ?string $apiKeyPrefix = null,
    ) {}
}
