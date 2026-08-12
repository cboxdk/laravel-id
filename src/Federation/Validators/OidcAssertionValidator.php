<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Validators;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Federation\ValueObjects\OidcConnectionConfig;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * Validates an OpenID Connect `id_token` (a JWS) against a connection's config.
 *
 * Security posture:
 *  - Signature verification is delegated to firebase/php-jwt (vetted, maintained).
 *  - The verification key(s) are pinned to RS256 via {@see Key}, so a token whose
 *    header advertises a different `alg` (e.g. `HS256`, `none`) is rejected —
 *    closing the classic algorithm-confusion hole.
 *  - `exp`/`nbf`/`iat` are enforced by the library; `iss` and `aud` are asserted
 *    against the connection's configured issuer and client id here.
 *
 * The connection config arrives typed, as an {@see OidcConnectionConfig}. Verification
 * material is taken in this order:
 *   1. `jwksUri` — the IdP's JWKS endpoint (discovered from its OIDC metadata).
 *      Preferred: it is fetched through the DNS-pinned SSRF gate and cached, and a
 *      signing-key rotation (new `kid`) is picked up automatically via a single forced
 *      refetch on a kid-miss — bounded to once/minute/connection so bad tokens can't
 *      amplify into a fetch flood. Keys are RS256-pinned exactly as the static ones.
 *   2. `signingKeys` — map of `kid` → PEM public key (JWKS-style, multi-key)
 *   3. `signingKey` — a single PEM public key (used when the IdP omits `kid`)
 */
class OidcAssertionValidator implements AssertionValidator
{
    private const ALG = 'RS256';

    public function __construct(private readonly Connections $connections) {}

    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal
    {
        $config = $this->connections->oidcConfig($connection);

        $claims = $this->decode($rawResponse, $config);

        $this->assertIssuer($claims, $config->issuer);
        $this->assertAudience($claims, $config->clientId);

        $subject = isset($claims['sub']) && is_string($claims['sub']) ? $claims['sub'] : null;

        if ($subject === null || $subject === '') {
            throw InvalidAssertion::make('missing subject (sub)');
        }

        return new FederatedPrincipal(
            provider: $connection->type->value,
            subject: $subject,
            email: $this->optionalString($claims, 'email'),
            name: $this->optionalString($claims, 'name'),
            connectionId: $connection->id,

            // OIDC Core §5.1: `email_verified` is a boolean the IdP asserts. Only an
            // explicit true carries over — a provider that omits it has not vouched for
            // the address, and absence is not a denial we should invent an answer for.
            emailVerified: ($claims['email_verified'] ?? null) === true ? true : null,

            raw: $claims,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function decode(string $idToken, OidcConnectionConfig $config): array
    {
        try {
            $decoded = JWT::decode($idToken, $this->keys($config));
        } catch (Throwable $exception) {
            // The IdP may have ROTATED its signing key (new kid) since we cached its
            // JWKS — a cached-set miss looks like a signature failure. Retry ONCE with a
            // freshly-fetched JWKS before giving up, so a customer key rollover doesn't
            // break every login until the cache TTL lapses. A fresh set can never make an
            // expired or tampered token valid, so the retry is safe.
            if ($this->mayRefresh($config)) {
                try {
                    $decoded = JWT::decode($idToken, $this->keys($config, forceRefresh: true));
                } catch (Throwable $retry) {
                    throw InvalidAssertion::make('signature or lifetime check failed: '.$retry->getMessage());
                }
            } else {
                throw InvalidAssertion::make('signature or lifetime check failed: '.$exception->getMessage());
            }
        }

        $claims = [];
        foreach (get_object_vars($decoded) as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return $claims;
    }

    /**
     * @return Key|array<string, Key>
     */
    private function keys(OidcConnectionConfig $config, bool $forceRefresh = false): Key|array
    {
        // Prefer the IdP's live JWKS when a jwks_uri is configured (discovered from the
        // OIDC metadata): fetching it means a signing-key rotation is picked up
        // automatically instead of breaking logins until an admin re-pastes PEMs.
        if ($config->jwksUri !== null) {
            $jwks = $this->fetchJwks($config->jwksUri, $forceRefresh);

            if (is_array($jwks)) {
                try {
                    // parseKeySet pins RS256 as the default alg for keys that omit one;
                    // JWT::decode still requires the token header alg to match the
                    // selected key's alg, so alg-confusion (alg:none, or HS256 signed
                    // with the RSA public key) stays closed exactly as with static PEMs.
                    $keys = JWK::parseKeySet($jwks, self::ALG);

                    if ($keys !== []) {
                        return $keys;
                    }
                } catch (Throwable) {
                    // Malformed JWKS — fall through to the admin-pasted static keys below.
                }
            }
        }

        if ($config->signingKeys !== []) {
            $keys = [];
            foreach ($config->signingKeys as $kid => $pem) {
                $keys[$kid] = new Key($pem, self::ALG);
            }

            return $keys;
        }

        if ($config->signingKey !== null) {
            return new Key($config->signingKey, self::ALG);
        }

        throw InvalidAssertion::make('connection has no signing key configured');
    }

    /**
     * Whether a kid-miss may trigger a forced JWKS refetch right now. Bounded to once
     * per minute per connection so a flood of bad tokens can't turn every failed
     * verification into a JWKS fetch — an amplification DoS against the upstream IdP.
     * A genuine key rotation is still picked up within the cooldown window.
     */
    private function mayRefresh(OidcConnectionConfig $config): bool
    {
        if ($config->jwksUri === null) {
            return false;
        }

        // Cache::add is atomic: true only the first time within the TTL.
        return Cache::add('oidc_jwks_refresh:'.hash('sha256', $config->jwksUri), true, 60);
    }

    /**
     * Fetch the IdP's JWKS through the same DNS-pinned SSRF gate as every other
     * admin-configured federation URL, and cache it for an hour. `$forceRefresh`
     * bypasses the cache after a kid-miss so a key rotation is picked up at once.
     * Returns null on any fetch/parse failure so the caller falls back to static keys.
     *
     * @return array<array-key, mixed>|null
     */
    private function fetchJwks(string $jwksUri, bool $forceRefresh): ?array
    {
        $cacheKey = 'oidc_jwks:'.hash('sha256', $jwksUri);

        if (! $forceRefresh) {
            $cached = Cache::get($cacheKey);

            if (is_array($cached)) {
                return $cached;
            }
        }

        try {
            $response = Http::withOptions(SafeFederationUrl::pinnedOptions($jwksUri))->timeout(10)->get($jwksUri);
        } catch (Throwable) {
            return null;
        }

        if (! $response->successful()) {
            return null;
        }

        $jwks = $response->json();

        if (! is_array($jwks) || ! isset($jwks['keys']) || ! is_array($jwks['keys'])) {
            return null;
        }

        Cache::put($cacheKey, $jwks, 3600);

        return $jwks;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertIssuer(array $claims, string $issuer): void
    {
        $iss = $claims['iss'] ?? null;

        if (! is_string($iss) || ! hash_equals($issuer, $iss)) {
            throw InvalidAssertion::make('issuer mismatch');
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertAudience(array $claims, string $clientId): void
    {
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];

        $matched = false;
        foreach ($audiences as $candidate) {
            if (is_string($candidate) && hash_equals($clientId, $candidate)) {
                $matched = true;
                break;
            }
        }

        if (! $matched) {
            throw InvalidAssertion::make('audience mismatch');
        }

        // OIDC Core §3.1.3.7 (3)-(5): when the id_token names more than one audience
        // it MUST carry an `azp` (authorized party), and whenever `azp` is present it
        // MUST equal our client_id. Without this, a token minted by a shared upstream
        // IdP for a *different* relying party — aud=[us, attacker], azp=attacker —
        // would be accepted here purely because our id appears in the aud array,
        // letting the attacker replay it into this connection.
        $realAudiences = array_values(array_filter(
            $audiences,
            static fn (mixed $candidate): bool => is_string($candidate) && $candidate !== '',
        ));

        $azp = $claims['azp'] ?? null;
        $azpPresent = is_string($azp) && $azp !== '';

        if (count($realAudiences) > 1 && ! $azpPresent) {
            throw InvalidAssertion::make('multi-audience id_token missing azp');
        }

        if ($azpPresent && ! hash_equals($clientId, $azp)) {
            throw InvalidAssertion::make('azp mismatch');
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function optionalString(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
