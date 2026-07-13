<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Dpop;

use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Cbox\Id\OAuthServer\Models\DpopProof;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Carbon;
use Throwable;
use UnexpectedValueException;

/**
 * Validates a DPoP proof JWT (RFC 9449) and returns the JWK SHA-256 thumbprint
 * (`jkt`, RFC 7638) the access token should be bound to — a sender-constrained
 * token that a stolen bearer alone cannot use.
 *
 * The proof is a JWT the client signs with a key it holds, carrying that key's
 * public half in the header (`jwk`). This verifies: the `dpop+jwt` type, an
 * allow-listed asymmetric alg, the embedded-key signature, that the proof was
 * made for this exact method+URL (`htm`/`htu`), that it is fresh (`iat`), and that
 * its `jti` has not been seen before (single-use, replay-proof).
 */
final class DpopProofValidator
{
    /** Asymmetric algs a proof may use — never a MAC, never `none`. */
    private const ALLOWED_ALGS = ['ES256', 'RS256', 'EdDSA'];

    /** How far the proof's `iat` may be from now, in seconds. */
    private const MAX_AGE_SECONDS = 60;

    /**
     * @param  string|null  $accessToken  when set (resource surface, RFC 9449 §4.3),
     *                                    the proof must carry `ath` = the token's SHA-256
     * @return string the base64url JWK thumbprint (jkt) to place in / match against `cnf`
     *
     * @throws InvalidDpopProof
     */
    public function verify(string $proof, string $htm, string $htu, ?string $accessToken = null): string
    {
        $header = $this->decodeSegment($proof, 0);
        $jwk = $header['jwk'] ?? null;

        if (($header['typ'] ?? null) !== 'dpop+jwt') {
            throw InvalidDpopProof::make('typ must be dpop+jwt');
        }

        $alg = $header['alg'] ?? null;
        if (! is_string($alg) || ! in_array($alg, self::ALLOWED_ALGS, true)) {
            throw InvalidDpopProof::make('unsupported alg');
        }

        if (! is_array($jwk) || isset($jwk['d'])) {
            throw InvalidDpopProof::make('header must carry the public jwk only');
        }

        // Verify the signature against the embedded public key.
        try {
            $key = JWK::parseKey($jwk, $alg);
            if ($key === null) {
                throw InvalidDpopProof::make('unparseable jwk');
            }
            $claims = (array) JWT::decode($proof, $key);
        } catch (InvalidDpopProof $e) {
            throw $e;
        } catch (UnexpectedValueException $e) {
            throw InvalidDpopProof::make($e->getMessage());
        } catch (Throwable) {
            throw InvalidDpopProof::make('signature verification failed');
        }

        $this->assertBinding($claims, $htm, $htu, $accessToken);
        $this->guardReplay($claims);

        return $this->thumbprint($jwk);
    }

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private function assertBinding(array $claims, string $htm, string $htu, ?string $accessToken = null): void
    {
        if (($claims['htm'] ?? null) !== strtoupper($htm)) {
            throw InvalidDpopProof::make('htm does not match the request method');
        }

        if (! is_string($claims['htu'] ?? null) || $this->normalizeUrl($claims['htu']) !== $this->normalizeUrl($htu)) {
            throw InvalidDpopProof::make('htu does not match the request URL');
        }

        // At a resource, the proof must be bound to the exact access token it
        // accompanies (RFC 9449 §4.3) — this stops a proof captured for one token
        // being replayed to authorize a different one.
        if ($accessToken !== null) {
            $expectedAth = $this->base64url(hash('sha256', $accessToken, true));

            if (! is_string($claims['ath'] ?? null) || ! hash_equals($expectedAth, $claims['ath'])) {
                throw InvalidDpopProof::make('ath does not match the access token');
            }
        }

        $iat = $claims['iat'] ?? null;
        if (! is_int($iat) && ! (is_float($iat) || is_string($iat) && is_numeric($iat))) {
            throw InvalidDpopProof::make('iat is missing');
        }

        if (abs(time() - (int) $iat) > self::MAX_AGE_SECONDS) {
            throw InvalidDpopProof::make('proof is stale');
        }
    }

    /**
     * @param  array<array-key, mixed>  $claims
     */
    private function guardReplay(array $claims): void
    {
        $jti = $claims['jti'] ?? null;
        if (! is_string($jti) || $jti === '') {
            throw InvalidDpopProof::make('jti is missing');
        }

        $iat = $claims['iat'] ?? null;
        $iat = is_numeric($iat) ? (int) $iat : time();

        try {
            DpopProof::query()->create([
                'jti' => $jti,
                'expires_at' => Carbon::createFromTimestamp($iat)->addSeconds(self::MAX_AGE_SECONDS),
            ]);
        } catch (UniqueConstraintViolationException) {
            throw InvalidDpopProof::make('proof replay detected');
        }
    }

    /**
     * RFC 7638 JWK thumbprint: SHA-256 over the canonical (lexicographically
     * ordered, whitespace-free) required members for the key type.
     *
     * @param  array<array-key, mixed>  $jwk
     */
    private function thumbprint(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;

        $canonical = match ($kty) {
            'EC' => ['crv' => $jwk['crv'] ?? null, 'kty' => 'EC', 'x' => $jwk['x'] ?? null, 'y' => $jwk['y'] ?? null],
            'RSA' => ['e' => $jwk['e'] ?? null, 'kty' => 'RSA', 'n' => $jwk['n'] ?? null],
            'OKP' => ['crv' => $jwk['crv'] ?? null, 'kty' => 'OKP', 'x' => $jwk['x'] ?? null],
            default => throw InvalidDpopProof::make('unsupported key type'),
        };

        foreach ($canonical as $value) {
            if (! is_string($value) || $value === '') {
                throw InvalidDpopProof::make('jwk is missing required members');
            }
        }

        $json = (string) json_encode($canonical, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return $this->base64url(hash('sha256', $json, true));
    }

    /**
     * @return array<array-key, mixed>
     */
    private function decodeSegment(string $jwt, int $index): array
    {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw InvalidDpopProof::make('malformed proof');
        }

        $decoded = json_decode((string) JWT::urlsafeB64Decode($segments[$index]), true);

        if (! is_array($decoded)) {
            throw InvalidDpopProof::make('malformed proof segment');
        }

        return $decoded;
    }

    /** Compare origin + path only (RFC 9449 §4.3), ignoring query and fragment. */
    private function normalizeUrl(string $url): string
    {
        $parts = parse_url($url);
        $parts = is_array($parts) ? $parts : [];

        $scheme = strtolower(is_string($parts['scheme'] ?? null) ? $parts['scheme'] : '');
        $host = strtolower(is_string($parts['host'] ?? null) ? $parts['host'] : '');
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $path = is_string($parts['path'] ?? null) ? rtrim($parts['path'], '/') : '';

        return $scheme.'://'.$host.$port.$path;
    }

    private function base64url(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
