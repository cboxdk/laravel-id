<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Illuminate\Support\Facades\Http;

/**
 * The relying-party half of an OpenID Connect connection: builds the authorization
 * request the browser is sent to, and exchanges the returned code for tokens at
 * the IdP's token endpoint. Signature/claim validation of the resulting id_token
 * is the {@see Validators\OidcAssertionValidator}'s job.
 *
 * OIDC connection config (sealed at rest) must add, alongside the validator's
 * `issuer`/`client_id`/`signing_key(s)`:
 *  - `authorization_endpoint`, `token_endpoint` — the IdP's OAuth endpoints
 *  - `client_secret` — the confidential client secret
 *  - `scopes` (optional) — defaults to `openid email profile`
 */
final class OidcClient
{
    public function __construct(private readonly Connections $connections) {}

    public function authorizeUrl(Connection $connection, string $redirectUri, string $state, string $nonce): string
    {
        $config = $this->connections->config($connection);

        $scopes = $config['scopes'] ?? null;
        $scope = is_array($scopes) && $scopes !== []
            ? implode(' ', array_filter($scopes, 'is_string'))
            : 'openid email profile';

        $endpoint = $this->require($config, 'authorization_endpoint');
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $this->require($config, 'client_id'),
            'redirect_uri' => $redirectUri,
            'scope' => $scope,
            'state' => $state,
            'nonce' => $nonce,
        ]);

        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?').$query;
    }

    /**
     * Exchange an authorization code for the id_token. Redirects are disabled and
     * a short timeout applies — the token endpoint is a direct server-to-server call.
     */
    public function exchangeCode(Connection $connection, string $code, string $redirectUri): string
    {
        $config = $this->connections->config($connection);

        $endpoint = $this->require($config, 'token_endpoint');

        // The token endpoint is org-admin-configured — hence untrusted. Guard it
        // like any other outbound URL (same SSRF mechanism as webhook delivery):
        // refuse internal/reserved addresses (e.g. cloud metadata) and pin the
        // connection to the validated IPs, closing DNS-rebinding (TOCTOU).
        try {
            $pinned = SafeFederationUrl::pinnedOptions($endpoint);
        } catch (UnsafeFederationUrl $e) {
            throw InvalidAssertion::make('token endpoint blocked: '.$e->getMessage());
        }

        $response = Http::asForm()
            ->withOptions($pinned)          // pinned resolution + no redirects
            ->withoutRedirecting()          // a 30x to an internal host must not be followed
            ->timeout(10)
            ->post($endpoint, [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'client_id' => $this->require($config, 'client_id'),
                'client_secret' => $this->require($config, 'client_secret'),
            ]);

        if (! $response->successful()) {
            throw InvalidAssertion::make('token exchange failed');
        }

        $idToken = $response->json('id_token');

        if (! is_string($idToken) || $idToken === '') {
            throw InvalidAssertion::make('token response contained no id_token');
        }

        return $idToken;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function require(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidAssertion::make("connection config missing [{$key}]");
        }

        return $value;
    }
}
