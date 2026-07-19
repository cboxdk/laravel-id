<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;

/**
 * The authorization-server metadata document, shared by the OIDC discovery
 * endpoint (`/.well-known/openid-configuration`) and the OAuth 2.0 Authorization
 * Server Metadata endpoint (RFC 8414, `/.well-known/oauth-authorization-server`)
 * that MCP clients fetch. Both serve the same document.
 */
final class ServerMetadata
{
    public static function issuer(): string
    {
        // Per-environment: discovery served at a tenant subdomain must advertise that
        // host as the issuer (and thus its jwks_uri), matching its per-env signing key.
        return app(IssuerResolver::class)->issuer();
    }

    /**
     * @return array<string, mixed>
     */
    public static function document(): array
    {
        $issuer = self::issuer();

        $document = [
            'issuer' => $issuer,
            'jwks_uri' => $issuer.'/.well-known/jwks.json',
            'token_endpoint' => $issuer.'/oauth/token',
            'introspection_endpoint' => $issuer.'/oauth/introspect',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            // OpenID Connect RP-Initiated Logout 1.0.
            'end_session_endpoint' => $issuer.'/oauth/logout',
            // RFC 9126: pushed authorization requests.
            'pushed_authorization_request_endpoint' => $issuer.'/oauth/par',
            'require_pushed_authorization_requests' => (bool) config('cbox-id.oauth.require_par', false),
            // RFC 8628: device authorization grant.
            'device_authorization_endpoint' => $issuer.'/oauth/device_authorization',
            // OIDC CIBA: client-initiated backchannel authentication (poll mode).
            'backchannel_authentication_endpoint' => $issuer.'/oauth/backchannel_authentication',
            'backchannel_token_delivery_modes_supported' => ['poll'],
            'backchannel_user_code_parameter_supported' => false,
            // RFC 9207: the authorization response carries `iss` (mix-up defense).
            'authorization_response_iss_parameter_supported' => true,
            'response_types_supported' => ['code'],
            // Code flow delivers the response on the redirect query; fragment is also
            // valid. The interactive /authorize endpoint (host-owned) drives these.
            'response_modes_supported' => ['query', 'fragment'],
            'grant_types_supported' => self::grantTypes(),
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'EdDSA'],
            'code_challenge_methods_supported' => ['S256'],
            // RFC 9449: sender-constrained (DPoP) access tokens.
            'dpop_signing_alg_values_supported' => ['ES256', 'RS256', 'EdDSA'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access', 'organizations'],
            'subject_types_supported' => ['public'],
            // The claims the id_token / UserInfo actually carry — honest, not aspirational.
            // Includes the non-standard federation claims (email_verified is standard;
            // roles/permissions/organizations are extensions a client can rely on).
            'claims_supported' => [
                'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr',
                'at_hash', 'email', 'email_verified', 'name', 'org', 'org_name',
                'roles', 'permissions', 'organizations',
            ],
            // The authentication context class references this IdP asserts: aal1 (a
            // single factor) and aal2 (a second factor was used at login).
            'acr_values_supported' => ['urn:cbox-id:aal1', 'urn:cbox-id:aal2'],
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'],
            // RFC 7523 client-assertion signing algs (private_key_jwt).
            'token_endpoint_auth_signing_alg_values_supported' => ['RS256', 'ES256', 'EdDSA'],
        ];

        // The interactive `/authorize` endpoint is the host app's responsibility;
        // advertise it only when the host has told us where it lives. Omitting the
        // key is valid per RFC 8414 rather than advertising a route we don't serve.
        $authorizationEndpoint = config('cbox-id.oauth.authorization_endpoint');

        if (is_string($authorizationEndpoint) && $authorizationEndpoint !== '') {
            $document['authorization_endpoint'] = $authorizationEndpoint;
        }

        // Advertise DCR only when it is actually enabled.
        if (config('cbox-id.oauth.dynamic_registration.mode', 'disabled') !== 'disabled') {
            $document['registration_endpoint'] = $issuer.'/oauth/register';
        }

        return $document;
    }

    /**
     * @return list<string>
     */
    private static function grantTypes(): array
    {
        return [
            'authorization_code',
            'client_credentials',
            'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code',
            'urn:openid:params:grant-type:ciba',
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ];
    }
}
