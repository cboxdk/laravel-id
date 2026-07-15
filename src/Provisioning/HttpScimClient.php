<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Provisioning\Contracts\ScimClient;
use Cbox\Id\Provisioning\Enums\AuthScheme;
use Cbox\Id\Provisioning\Exceptions\UnsafeScimUrl;
use Cbox\Id\Provisioning\Models\ProvisioningConnection;
use Cbox\Id\Provisioning\Support\SafeScimUrl;
use Cbox\Id\Provisioning\ValueObjects\ScimResult;
use Cbox\Id\Scim\ScimSchema;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * The outbound SCIM 2.0 HTTP client. Every request is TLS-verified, carries the
 * `application/scim+json` content type, and is pinned to the IPs resolved by the
 * SSRF guard immediately before sending (so a DNS rebind between check and connect
 * cannot redirect it to an internal address — TOCTOU-closed), with redirects
 * refused (a 30x to an internal host must not be followed).
 *
 * The Authorization header is built from the connection's sealed secret and never
 * stored, logged, or placed in a returned {@see ScimResult}: an
 * {@see UnsafeScimUrl} carries only the URL reason, and a failed HTTP response is
 * reduced to its status + SCIM `detail`.
 */
final class HttpScimClient implements ScimClient
{
    /**
     * Per-connection OAuth access-token cache, so a client-credentials grant is not
     * repeated for every operation. Each entry carries the token's expiry (from the
     * grant's `expires_in`, minus a safety margin) — the client is a container
     * singleton and lives across many jobs in a long-running worker, so a cache with
     * no expiry would keep serving a token past its life and every op would then 401
     * and dead-letter until the worker restarted. An expired entry is refreshed.
     *
     * @var array<string, array{token: string, expires_at: int}>
     */
    private array $tokenCache = [];

    /** Refresh a cached token this many seconds BEFORE its stated expiry (clock skew). */
    private const TOKEN_EXPIRY_MARGIN = 30;

    /** Fallback lifetime when a token endpoint omits `expires_in`. */
    private const TOKEN_DEFAULT_TTL = 300;

    public function __construct(private readonly SecretBox $secretBox) {}

    public function createUser(ProvisioningConnection $connection, array $resource): ScimResult
    {
        $url = $connection->usersEndpoint();

        return $this->send($connection, $url, fn (PendingRequest $request): Response => $request
            ->withBody(self::encode($resource), ScimSchema::CONTENT_TYPE)
            ->post($url));
    }

    public function patchUser(ProvisioningConnection $connection, string $remoteId, array $operations): ScimResult
    {
        $url = $connection->userEndpoint($remoteId);

        return $this->send($connection, $url, fn (PendingRequest $request): Response => $request
            ->withBody(self::encode(ScimSchema::patchOp($operations)), ScimSchema::CONTENT_TYPE)
            ->patch($url));
    }

    public function deleteUser(ProvisioningConnection $connection, string $remoteId): ScimResult
    {
        $url = $connection->userEndpoint($remoteId);

        return $this->send($connection, $url, fn (PendingRequest $request): Response => $request->delete($url));
    }

    public function findByExternalId(ProvisioningConnection $connection, string $externalId): ?string
    {
        $url = $connection->usersEndpoint();
        $filter = ScimSchema::equalityFilter('externalId', $externalId);

        $result = $this->send($connection, $url, fn (PendingRequest $request): Response => $request
            ->get($url, ['filter' => $filter]));

        // Only adopt a remote record that actually carries our externalId, and only
        // when the response is unambiguous — a peer that ignores the filter and
        // returns its whole list must never bind an arbitrary user as this mirror.
        return $result->successful() ? $result->resourceIdForExternalId($externalId) : null;
    }

    /**
     * Guard + pin the URL, attach auth and SCIM headers, run the request, and
     * normalize the outcome. A blocked URL or transport failure becomes a
     * transient {@see ScimResult} rather than an exception escaping to the drain.
     *
     * @param  callable(PendingRequest): Response  $perform
     */
    private function send(ProvisioningConnection $connection, string $url, callable $perform): ScimResult
    {
        try {
            $pinned = SafeScimUrl::pinnedOptions($url);
            $authorization = $this->authorization($connection);
        } catch (Throwable) {
            // A connection pointed at a private/metadata address (UnsafeScimUrl),
            // or a token-endpoint that could not be reached, is treated as a
            // transient failure — so the drain retries rather than dead-lettering
            // a misconfiguration an operator can still correct. No secret escapes.
            return ScimResult::transportError();
        }

        try {
            $request = Http::withHeaders([
                'Authorization' => $authorization,
                'Accept' => ScimSchema::CONTENT_TYPE,
            ])
                ->withOptions($pinned)   // pinned resolution + no redirects
                ->withoutRedirecting()   // a 30x to an internal host must not be followed
                ->connectTimeout(5)
                ->timeout(15);

            $response = $perform($request);
        } catch (Throwable) {
            return ScimResult::transportError();
        }

        return ScimResult::http($response->status(), self::decode($response));
    }

    /**
     * Build the `Authorization` header from the connection's sealed secret —
     * either the bearer token directly, or a fresh OAuth client-credentials token.
     */
    private function authorization(ProvisioningConnection $connection): string
    {
        $secret = $this->secretBox->open($connection->auth_secret_encrypted, $connection->secretContext());

        return match ($connection->auth_scheme) {
            AuthScheme::Bearer => 'Bearer '.$secret,
            AuthScheme::OAuth2ClientCredentials => 'Bearer '.$this->clientCredentialsToken($connection, $secret),
        };
    }

    /**
     * Exchange the sealed client secret at the connection's token endpoint for a
     * short-lived access token (OAuth 2.0 client-credentials, RFC 6749 §4.4) via
     * the standard HTTP client — no hand-rolled OAuth. The token URL is
     * SSRF-guarded exactly like the SCIM base URL.
     */
    private function clientCredentialsToken(ProvisioningConnection $connection, string $clientSecret): string
    {
        $cached = $this->tokenCache[$connection->id] ?? null;

        if ($cached !== null && $cached['expires_at'] > now()->getTimestamp()) {
            return $cached['token'];
        }

        $config = $connection->auth_config;
        $tokenUrl = is_string($config['token_url'] ?? null) ? $config['token_url'] : '';
        $clientId = is_string($config['client_id'] ?? null) ? $config['client_id'] : '';
        $scope = is_string($config['scope'] ?? null) ? $config['scope'] : null;

        SafeScimUrl::assert($tokenUrl);
        $pinned = SafeScimUrl::pinnedOptions($tokenUrl);

        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];

        if ($scope !== null && $scope !== '') {
            $form['scope'] = $scope;
        }

        $response = Http::asForm()
            ->withOptions($pinned)
            ->withoutRedirecting()
            ->connectTimeout(5)
            ->timeout(15)
            ->post($tokenUrl, $form);

        $token = $response->json('access_token');

        if (! is_string($token) || $token === '') {
            // Surface a secret-free failure the drain treats as transient.
            throw UnsafeScimUrl::make('OAuth token endpoint returned no access_token');
        }

        $expiresIn = $response->json('expires_in');
        $ttl = is_int($expiresIn) && $expiresIn > 0 ? $expiresIn : self::TOKEN_DEFAULT_TTL;

        $this->tokenCache[$connection->id] = [
            'token' => $token,
            'expires_at' => now()->getTimestamp() + max(1, $ttl - self::TOKEN_EXPIRY_MARGIN),
        ];

        return $token;
    }

    /**
     * @param  array<string, mixed>  $body
     */
    private static function encode(array $body): string
    {
        return json_encode($body, JSON_THROW_ON_ERROR);
    }

    /**
     * @return array<string, mixed>
     */
    private static function decode(Response $response): array
    {
        $decoded = $response->json();

        if (! is_array($decoded)) {
            return [];
        }

        $body = [];
        foreach ($decoded as $key => $value) {
            $body[(string) $key] = $value;
        }

        return $body;
    }
}
