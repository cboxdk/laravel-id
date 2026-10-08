<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\ValueObjects;

use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
use Cbox\Id\Federation\OidcClient;

/**
 * The endpoints resolved from an OpenID Provider's discovery document
 * (`/.well-known/openid-configuration`, OpenID Connect Discovery 1.0). A PREFILL
 * for the connection form so an admin pastes only the issuer instead of hand-copying
 * the authorization and token endpoints (which {@see OidcClient}
 * requires) — the classic source of half-configured OIDC connections.
 */
readonly class DiscoveredOidcProvider
{
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public ?string $jwksUri = null,
        public ?string $userinfoEndpoint = null,

        /**
         * `token_endpoint_auth_methods_supported`, as the document listed it — empty when
         * it did not say. Kept raw so a console can show what the provider claims; the
         * decision is {@see self::tokenEndpointAuthMethod()}.
         *
         * @var list<string>
         */
        public array $tokenEndpointAuthMethods = [],
    ) {}

    /** How the OIDC client should present the secret at this provider's token endpoint. */
    public function tokenEndpointAuthMethod(): TokenEndpointAuthMethod
    {
        return TokenEndpointAuthMethod::forAdvertised($this->tokenEndpointAuthMethods);
    }

    /** Whether every endpoint the OIDC client requires was present. */
    public function isComplete(): bool
    {
        return $this->authorizationEndpoint !== '' && $this->tokenEndpoint !== '';
    }

    /**
     * The connection-config keys the OIDC client expects, merged with the
     * admin-supplied client_id/secret/signing key when the connection is saved.
     *
     * @return array<string, string>
     */
    public function toConfig(): array
    {
        $config = [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->authorizationEndpoint,
            'token_endpoint' => $this->tokenEndpoint,
        ];

        if ($this->jwksUri !== null && $this->jwksUri !== '') {
            $config['jwks_uri'] = $this->jwksUri;
        }

        if ($this->userinfoEndpoint !== null && $this->userinfoEndpoint !== '') {
            $config['userinfo_endpoint'] = $this->userinfoEndpoint;
        }

        // Only when it differs from what the client has always done, so a connection
        // saved from a provider that takes the body form stores exactly what it did
        // before this key existed.
        if ($this->tokenEndpointAuthMethod() !== TokenEndpointAuthMethod::ClientSecretPost) {
            $config['token_endpoint_auth_method'] = $this->tokenEndpointAuthMethod()->value;
        }

        return $config;
    }
}
