<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Illuminate\Http\JsonResponse;

/**
 * `GET /.well-known/openid-configuration` — OIDC discovery document.
 */
final class DiscoveryController
{
    public function __invoke(): JsonResponse
    {
        $configured = config('cbox-id.issuer');
        $issuer = is_string($configured) && $configured !== ''
            ? rtrim($configured, '/')
            : rtrim(url('/'), '/');

        return response()->json([
            'issuer' => $issuer,
            'jwks_uri' => $issuer.'/.well-known/jwks.json',
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'introspection_endpoint' => $issuer.'/oauth/introspect',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'client_credentials', 'refresh_token'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256'],
            'code_challenge_methods_supported' => ['S256'],
            'scopes_supported' => ['openid', 'profile', 'email'],
            'subject_types_supported' => ['public'],
        ]);
    }
}
