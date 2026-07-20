<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ClientAssertion;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\ClientAssertion;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Models\Client;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Cache\Repository as Cache;
use Throwable;

/**
 * `private_key_jwt` client authentication (RFC 7523 §3 / OIDC Core §9). Instead of a
 * shared secret, a confidential client signs a short-lived assertion with its private
 * key; this verifies it against the client's REGISTERED public JWK Set.
 *
 * Deny-by-default, mirroring the DPoP validator: an asymmetric alg from an allow-list
 * (never `none`, never a MAC), `iss == sub == client_id`, a signature that checks
 * against the client's keys, an audience that is this authorization server, an
 * unexpired assertion (firebase's decoder enforces `exp`), and a single-use `jti`
 * (replay-guarded in the shared cache — no second table).
 */
class ClientAssertionValidator implements ClientAssertion
{
    /** Asymmetric signing algs a client assertion may use. */
    private const ALLOWED_ALGS = ['RS256', 'ES256', 'EdDSA'];

    private const REPLAY_PREFIX = 'cbox:client-assertion:jti:';

    /**
     * The longest lifetime a client assertion may claim. RFC 7523 assertions are
     * one-shot proofs, not sessions — a short cap bounds both the replay window and
     * how long the single-use `jti` must be remembered.
     */
    private const MAX_LIFETIME_SECONDS = 300;

    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly IssuerResolver $issuers,
        private readonly Cache $cache,
    ) {}

    /**
     * Verify a client assertion; returns the authenticated client, or null for
     * anything invalid (unknown client, no registered keys, bad signature/alg,
     * wrong audience, expired, replayed, or iss≠sub).
     */
    public function verify(string $assertion): ?Client
    {
        $header = $this->segment($assertion, 0);
        $alg = $header['alg'] ?? null;

        if (! is_string($alg) || ! in_array($alg, self::ALLOWED_ALGS, true)) {
            return null;
        }

        // Read the (unverified) claims only to locate the client — the signature is
        // checked below against that client's registered keys.
        $claims = $this->segment($assertion, 1);
        $iss = $claims['iss'] ?? null;
        $sub = $claims['sub'] ?? null;

        // RFC 7523 §3: for client authentication iss and sub are BOTH the client id.
        if (! is_string($sub) || $sub === '' || $iss !== $sub) {
            return null;
        }

        $client = $this->clients->byClientId($sub);

        if ($client === null || ! is_array($client->jwks) || $client->jwks === []) {
            return null;
        }

        try {
            // parseKeySet + decode picks the key by the assertion's `kid` and enforces
            // exp/nbf/iat. A signature/exp failure throws → treated as auth failure.
            $verified = (array) JWT::decode($assertion, JWK::parseKeySet($client->jwks));
        } catch (Throwable) {
            return null;
        }

        if (! $this->audienceValid($verified['aud'] ?? null)) {
            return null;
        }

        // RFC 7523 §3: `exp` is REQUIRED. firebase only enforces `exp` when present,
        // so require it explicitly — an assertion with no (or an over-long) lifetime
        // would otherwise get a ~1-second replay guard and be replayable. Bound the
        // lifetime so the single-use `jti` window is always meaningful.
        if (! $this->lifetimeValid($verified)) {
            return null;
        }

        return $this->consumeJti($sub, $verified) ? $client : null;
    }

    /**
     * A conformant assertion carries a numeric, still-future `exp` and `iat`, and a
     * lifetime no longer than {@see MAX_LIFETIME_SECONDS}.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function lifetimeValid(array $claims): bool
    {
        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;

        if (! is_numeric($exp) || ! is_numeric($iat)) {
            return false;
        }

        $exp = (int) $exp;
        $iat = (int) $iat;
        $now = time();

        // `exp` still in the future (firebase already rejected a past one, but be
        // explicit), `iat` not from the future, and a bounded lifetime.
        return $exp > $now
            && $iat <= $now + 60
            && $exp - $iat > 0
            && $exp - $iat <= self::MAX_LIFETIME_SECONDS;
    }

    /** The assertion's audience must name THIS authorization server (issuer or token endpoint). */
    private function audienceValid(mixed $aud): bool
    {
        $issuer = rtrim($this->issuers->issuer(), '/');
        $accepted = [$issuer, $issuer.'/oauth/token'];

        foreach (is_array($aud) ? $aud : [$aud] as $candidate) {
            if (is_string($candidate) && in_array(rtrim($candidate, '/'), $accepted, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Single-use: atomically claim the assertion's jti (scoped to the client) until
     * it expires. A replay finds it already taken.
     *
     * @param  array<array-key, mixed>  $claims
     */
    private function consumeJti(string $clientId, array $claims): bool
    {
        $jti = $claims['jti'] ?? null;

        if (! is_string($jti) || $jti === '') {
            return false;
        }

        $exp = $claims['exp'] ?? 0;
        $ttl = max(1, (is_numeric($exp) ? (int) $exp : 0) - time());

        return $this->cache->add(self::REPLAY_PREFIX.hash('sha256', $clientId.':'.$jti), true, $ttl);
    }

    /**
     * @return array<mixed>
     */
    private function segment(string $jwt, int $index): array
    {
        $parts = explode('.', $jwt);

        if (! isset($parts[$index])) {
            return [];
        }

        $decoded = json_decode(JWT::urlsafeB64Decode($parts[$index]), true);

        return is_array($decoded) ? $decoded : [];
    }
}
