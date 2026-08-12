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
    public function __construct(
        private readonly Connections $connections,
        private readonly AppleClientSecret $signedSecrets,
    ) {}

    public function authorizeUrl(Connection $connection, string $redirectUri, string $state, string $nonce): string
    {
        $config = $this->connections->oidcConfig($connection);

        $endpoint = $config->requireField($config->authorizationEndpoint, 'authorization_endpoint');
        $query = http_build_query(array_filter([
            'response_type' => 'code',
            'client_id' => $config->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $config->scopeString(),
            'state' => $state,
            'nonce' => $nonce,

            // ONLY WHEN THE PROVIDER REQUIRES ONE. Apple switches to `form_post` by
            // itself the moment a scope beyond `openid` is asked for, so a request that
            // stays silent here does not get the query-string redirect it was written
            // for — it gets a POST, to a handler that never runs, and the person sees
            // what looks like a cancellation. Declaring it makes the callback method a
            // property of the connection instead of a consequence of the scope list.
            'response_mode' => $this->responseMode($connection),
        ], static fn (?string $value): bool => $value !== null && $value !== ''));

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
                'client_secret' => $this->clientSecret($connection, $config),
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
     * The credential this connection authenticates to the token endpoint with.
     *
     * Most providers issue a string the administrator pastes once. Apple issues nothing
     * of the kind: it expects an ES256 JWT signed with a key you downloaded, valid at
     * most six months. Stored as a pasted string, that assertion works — and then stops
     * working on a day nobody changed anything, with an error indistinguishable from a
     * wrong client id. Minted per request, it cannot expire on its own.
     *
     * The connection's own material decides, not the catalogue: a connection carrying a
     * signing key mints, whatever it calls itself. That keeps a hand-configured OIDC
     * connection — no catalogue key at all — able to use the same authentication.
     */
    private function clientSecret(Connection $connection, OidcConnectionConfig $config): string
    {
        $credential = $config->signingCredential;

        if ($credential === null) {
            return $config->requireField($config->clientSecret, 'client_secret');
        }

        return $this->signedSecrets->mint(
            $connection->id,
            $credential->issuerId,
            $credential->keyId,
            $credential->privateKey,
            $config->clientId,
        );
    }

    /**
     * The `response_mode` the catalogue declares for this provider, if any.
     *
     * A connection with no catalogue key is hand-configured, and a hand-configured
     * connection gets the default: we have nothing to declare on its behalf.
     */
    private function responseMode(Connection $connection): ?string
    {
        $provider = $connection->provider;

        return $provider === null ? null : ProviderCatalog::find($provider)?->responseMode;
    }
}
