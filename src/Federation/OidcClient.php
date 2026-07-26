<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Federation\ValueObjects\OidcConnectionConfig;
use Illuminate\Support\Facades\Http;

/**
 * The relying-party half of an OpenID Connect connection: builds the authorization
 * request the browser is sent to, and exchanges the returned code for tokens at
 * the IdP's token endpoint. Signature/claim validation of the resulting id_token
 * is the {@see Validators\OidcAssertionValidator}'s job.
 *
 * Beyond what the validator needs, this half requires the connection's
 * `authorizationEndpoint`, `tokenEndpoint` and `clientSecret` — asserted here, at the
 * point of use, so a validator-only connection is not forced to carry them. See
 * {@see OidcConnectionConfig}.
 */
class OidcClient implements OidcRelyingParty
{
    public function __construct(private readonly Connections $connections) {}

    public function authorizeUrl(Connection $connection, string $redirectUri, string $state, string $nonce): string
    {
        $config = $this->connections->oidcConfig($connection);

        $endpoint = $config->requireField($config->authorizationEndpoint, 'authorization_endpoint');
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $config->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $config->scopeString(),
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
        $config = $this->connections->oidcConfig($connection);

        $endpoint = $config->requireField($config->tokenEndpoint, 'token_endpoint');

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
                'client_id' => $config->clientId,
                'client_secret' => $config->requireField($config->clientSecret, 'client_secret'),
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
}
