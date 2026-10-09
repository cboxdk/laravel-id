<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes;

use Cbox\Id\Federation\Enums\TokenEndpointAuthMethod;
use Cbox\Id\Kernel\Ssrf\UrlVerification;
use Cbox\Id\Pipes\Enums\RevocationStyle;
use Cbox\Id\Pipes\Enums\TokenRequestFormat;
use Cbox\Id\Pipes\Exceptions\PipeProviderUnavailable;
use Cbox\Id\Pipes\Exceptions\PipeTokenRejected;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\ValueObjects\PipeProvider;
use Cbox\Id\Pipes\ValueObjects\PipeTokenSet;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * The HTTP half of Pipes: the authorization URL, the code exchange, the refresh, the
 * revocation and the "who is this account" lookup — against the endpoints the CATALOGUE
 * names, never ones a tenant typed.
 *
 * What it never does is let a credential out. Error responses are reduced to the
 * provider's error CODE ({@see PipeTokenRejected}); the body, which some providers fill by
 * echoing the submitted token back, is dropped on the floor. Nothing here logs.
 *
 * Every request is SSRF-pinned. The endpoints are the catalogue's, but two of them carry
 * an administrator's parameter (Microsoft's tenant, Salesforce's domain), and the pattern
 * on each parameter is the first line of defence while the pin is the second.
 */
class PipeOAuthClient
{
    /** A PKCE code verifier: 64 characters of base64url, inside RFC 7636's 43–128. */
    public static function codeVerifier(): string
    {
        return self::base64Url(random_bytes(48));
    }

    /** The S256 challenge for a verifier (RFC 7636 §4.2). */
    public static function codeChallenge(string $verifier): string
    {
        return self::base64Url(hash('sha256', $verifier, true));
    }

    /**
     * Where to send the person to consent.
     *
     * @param  list<string>  $scopes
     */
    public function authorizeUrl(PipeProvider $provider, Pipe $pipe, array $scopes, string $redirectUri, string $state, string $codeChallenge): string
    {
        $endpoint = $provider->endpoint($provider->authorizationEndpoint, $pipe->parameterValues());

        $query = [
            'response_type' => 'code',
            'client_id' => $pipe->client_id,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            // Always sent. A provider that does not implement PKCE ignores both parameters
            // (RFC 7636 §5), and every one that does gains a code an interceptor cannot use.
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ];

        if ($scopes !== []) {
            $query[$provider->scopeParameter] = $provider->scopeString($scopes);
        }

        $query += $provider->authorizeParameters;

        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?').http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchange an authorization code for the person's tokens.
     *
     * @throws PipeTokenRejected when the provider refused the code
     * @throws PipeProviderUnavailable when it could not be asked
     */
    public function exchange(PipeProvider $provider, Pipe $pipe, string $clientSecret, string $code, string $redirectUri, string $codeVerifier): PipeTokenSet
    {
        $json = $this->tokenRequest($provider, $pipe, $clientSecret, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ]);

        $tokens = $this->tokenSet($provider, $json);

        if ($tokens->accountLabel !== null || $provider->accountEndpoint === null) {
            return $tokens;
        }

        return new PipeTokenSet(
            $tokens->accessToken,
            $tokens->refreshToken,
            $tokens->expiresIn,
            $tokens->scopes,
            $tokens->metadata,
            $this->accountLabel($provider, $pipe, $tokens->accessToken),
        );
    }

    /**
     * Spend a refresh token for a new access token (and, from providers that rotate, a new
     * refresh token).
     *
     * @throws PipeTokenRejected when the provider refused it — see {@see PipeTokenRejected::revokesTheGrant()}
     * @throws PipeProviderUnavailable when it could not be asked
     */
    public function refresh(PipeProvider $provider, Pipe $pipe, string $clientSecret, string $refreshToken): PipeTokenSet
    {
        $json = $this->tokenRequest($provider, $pipe, $clientSecret, [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);

        return $this->tokenSet($provider, $json);
    }

    /**
     * Ask the provider to revoke the person's authorization. Best effort: true when the
     * provider confirmed it, false when it has no revocation endpoint, refused, or could
     * not be reached. A disconnect forgets the tokens locally either way.
     */
    public function revoke(PipeProvider $provider, Pipe $pipe, string $clientSecret, string $accessToken, ?string $refreshToken): bool
    {
        $revocation = $provider->revocation;

        if ($revocation === null) {
            return false;
        }

        $token = $revocation->prefersRefreshToken && $refreshToken !== null ? $refreshToken : $accessToken;

        try {
            $response = match ($revocation->style) {
                RevocationStyle::Rfc7009 => $this->authenticated($provider, $pipe, $clientSecret, $provider->endpoint($revocation->endpoint, $pipe->parameterValues()), [
                    'token' => $token,
                    'token_type_hint' => $token === $refreshToken ? 'refresh_token' : 'access_token',
                ]),
                RevocationStyle::BearerToken => $this->request($url = $provider->endpoint($revocation->endpoint, $pipe->parameterValues()))
                    ->withToken($accessToken)
                    ->asForm()
                    ->post($url),
                RevocationStyle::GitHubGrant => $this->githubGrant($provider, $pipe, $clientSecret, $revocation->endpoint, $accessToken),
                RevocationStyle::RefreshTokenInPath => $refreshToken === null
                    ? null
                    : $this->request($url = $provider->endpoint($revocation->endpoint, $pipe->parameterValues(), ['refresh_token' => $refreshToken]))->delete($url),
            };
        } catch (Throwable) {
            return false;
        }

        if ($response === null || ! $response->successful()) {
            return false;
        }

        // Slack answers 200 with `ok: false` for a refusal.
        $body = $response->json();

        return ! (is_array($body) && ($body['ok'] ?? true) === false);
    }

    private function githubGrant(PipeProvider $provider, Pipe $pipe, string $clientSecret, string $endpoint, string $accessToken): Response
    {
        $url = $provider->endpoint($endpoint, $pipe->parameterValues(), ['client_id' => $pipe->client_id]);

        return $this->request($url)
            ->withHeaders([
                'Accept' => 'application/vnd.github+json',
                'Authorization' => TokenEndpointAuthMethod::basicCredentials($pipe->client_id, $clientSecret),
            ])
            ->asJson()
            ->delete($url, ['access_token' => $accessToken]);
    }

    /**
     * A form POST authenticated the way the provider's token endpoint expects.
     *
     * @param  array<string, string>  $form
     */
    private function authenticated(PipeProvider $provider, Pipe $pipe, string $clientSecret, string $url, array $form): Response
    {
        $request = $this->request($url);

        if ($provider->tokenEndpointAuthMethod === TokenEndpointAuthMethod::ClientSecretBasic) {
            $request = $request->withHeaders(['Authorization' => TokenEndpointAuthMethod::basicCredentials($pipe->client_id, $clientSecret)]);
        } else {
            $form['client_id'] = $pipe->client_id;
            $form['client_secret'] = $clientSecret;
        }

        return $request->asForm()->post($url, $form);
    }

    /**
     * @param  array<string, string>  $body
     * @return array<mixed>
     *
     * @throws PipeTokenRejected
     * @throws PipeProviderUnavailable
     */
    private function tokenRequest(PipeProvider $provider, Pipe $pipe, string $clientSecret, array $body): array
    {
        $url = $provider->endpoint($provider->tokenEndpoint, $pipe->parameterValues());
        $request = $this->request($url);

        // ONE client authentication method, never both (RFC 6749 §2.3).
        if ($provider->tokenEndpointAuthMethod === TokenEndpointAuthMethod::ClientSecretBasic) {
            $request = $request->withHeaders(['Authorization' => TokenEndpointAuthMethod::basicCredentials($pipe->client_id, $clientSecret)]);
        } else {
            $body['client_id'] = $pipe->client_id;
            $body['client_secret'] = $clientSecret;
        }

        try {
            $response = $provider->tokenRequestFormat === TokenRequestFormat::Json
                ? $request->asJson()->post($url, $body)
                : $request->asForm()->post($url, $body);
        } catch (ConnectionException) {
            throw PipeProviderUnavailable::because('unreachable');
        }

        if ($response->status() === 429 || $response->serverError()) {
            throw PipeProviderUnavailable::because('http_'.$response->status());
        }

        $json = $response->json();

        if (! is_array($json)) {
            if ($response->successful()) {
                throw PipeProviderUnavailable::because('malformed_response');
            }

            throw new PipeTokenRejected('http_'.$response->status(), $response->status());
        }

        // Slack answers 200 with `ok: false`; GitHub answers 200 with an `error`; HubSpot
        // answers 400 with a `status` code instead of `error`. All three are refusals.
        $error = $json['error'] ?? null;

        if (! is_string($error) && ! $response->successful()) {
            $error = is_string($json['status'] ?? null) ? $json['status'] : 'http_'.$response->status();
        }

        if (($json['ok'] ?? true) === false && ! is_string($error)) {
            $error = 'unknown_error';
        }

        if (is_string($error) && $error !== '') {
            throw new PipeTokenRejected(mb_substr($error, 0, 64), $response->status());
        }

        return $json;
    }

    /**
     * @param  array<mixed>  $json
     *
     * @throws PipeProviderUnavailable when there is no access token in it
     */
    private function tokenSet(PipeProvider $provider, array $json): PipeTokenSet
    {
        $root = $json;

        if ($provider->tokenResponsePath !== null) {
            $nested = data_get($json, $provider->tokenResponsePath);

            // A refresh answers at the top level even where the first exchange nested the
            // person's token (Slack's rotation), so the nested set is used only when present.
            if (is_array($nested) && is_string($nested['access_token'] ?? null)) {
                $root = $nested;
            }
        }

        $access = $root['access_token'] ?? null;

        if (! is_string($access) || $access === '') {
            throw PipeProviderUnavailable::because('no_access_token');
        }

        $refresh = $root['refresh_token'] ?? null;
        $expiresIn = $root['expires_in'] ?? null;

        $metadata = [];

        foreach ($provider->metadataPaths as $path) {
            $value = data_get($json, $path);

            if (is_string($value) || is_int($value) || is_float($value) || is_bool($value)) {
                $metadata[$path] = is_bool($value) ? ($value ? 'true' : 'false') : (string) $value;
            }
        }

        $label = $provider->accountLabelTokenPath === null ? null : data_get($json, $provider->accountLabelTokenPath);

        return new PipeTokenSet(
            accessToken: $access,
            refreshToken: is_string($refresh) && $refresh !== '' ? $refresh : null,
            expiresIn: is_numeric($expiresIn) && (int) $expiresIn > 0 ? (int) $expiresIn : null,
            scopes: $this->scopes($root['scope'] ?? null),
            metadata: $metadata,
            accountLabel: is_string($label) && $label !== '' ? mb_substr($label, 0, 255) : null,
        );
    }

    /**
     * Providers separate granted scopes with spaces (RFC 6749 §3.3), commas (GitHub,
     * Slack, Linear), or return a list.
     *
     * @return list<string>|null
     */
    private function scopes(mixed $scope): ?array
    {
        if (is_array($scope)) {
            return array_values(array_filter($scope, static fn (mixed $s): bool => is_string($s) && $s !== ''));
        }

        if (! is_string($scope)) {
            return null;
        }

        return array_values(array_filter(preg_split('/[\s,]+/', $scope) ?: [], static fn (string $s): bool => $s !== ''));
    }

    /**
     * The connected account's name, for the person's own list. Best effort: a provider
     * that is slow or refuses the call costs the label, never the connection.
     */
    private function accountLabel(PipeProvider $provider, Pipe $pipe, string $accessToken): ?string
    {
        if ($provider->accountEndpoint === null || $provider->accountLabelPath === null) {
            return null;
        }

        try {
            $url = $provider->endpoint($provider->accountEndpoint, $pipe->parameterValues());
            $response = $this->request($url)->withToken($accessToken)->get($url);
        } catch (Throwable) {
            return null;
        }

        if (! $response->successful()) {
            return null;
        }

        $label = $response->json($provider->accountLabelPath);

        return is_string($label) && $label !== '' ? mb_substr($label, 0, 255) : null;
    }

    private function request(string $url): PendingRequest
    {
        $timeout = config('cbox-id.pipes.http_timeout', 10);

        return Http::withOptions($this->pinned($url))
            ->withoutRedirecting()
            ->withHeaders([
                'Accept' => 'application/json',
                // GitHub refuses requests without one, with a 403 that reads as a
                // permissions problem.
                'User-Agent' => 'cbox-id',
            ])
            ->timeout(is_numeric($timeout) ? (int) $timeout : 10);
    }

    /**
     * @return array<string, mixed>
     *
     * @throws PipeProviderUnavailable when the endpoint resolves somewhere it must not
     */
    private function pinned(string $url): array
    {
        if (! UrlVerification::enforced('cbox-id.pipes.verify_url')) {
            // Redirects stay refused even with verification off — see SafeFederationUrl.
            return ['allow_redirects' => false];
        }

        try {
            return app(UrlGuard::class)->pinnedOptions($url);
        } catch (BlockedUrl) {
            throw PipeProviderUnavailable::because('endpoint_blocked');
        }
    }

    private static function base64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
