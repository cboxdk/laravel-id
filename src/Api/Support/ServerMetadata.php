<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

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
        $configured = config('cbox-id.issuer');

        return is_string($configured) && $configured !== ''
            ? rtrim($configured, '/')
            : rtrim(url('/'), '/');
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
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'introspection_endpoint' => $issuer.'/oauth/introspect',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            // RFC 9126: pushed authorization requests.
            'pushed_authorization_request_endpoint' => $issuer.'/oauth/par',
            'require_pushed_authorization_requests' => (bool) config('cbox-id.oauth.require_par', false),
            // RFC 8628: device authorization grant.
            'device_authorization_endpoint' => $issuer.'/oauth/device_authorization',
            // RFC 9207: the authorization response carries `iss` (mix-up defense).
            'authorization_response_iss_parameter_supported' => true,
            'response_types_supported' => ['code'],
            'grant_types_supported' => self::grantTypes(),
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'EdDSA'],
            'code_challenge_methods_supported' => ['S256'],
            // RFC 9449: sender-constrained (DPoP) access tokens.
            'dpop_signing_alg_values_supported' => ['ES256', 'RS256', 'EdDSA'],
            'scopes_supported' => ['openid', 'profile', 'email', 'offline_access'],
            'subject_types_supported' => ['public'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        ];

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
        return ['authorization_code', 'client_credentials', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'];
    }
}
