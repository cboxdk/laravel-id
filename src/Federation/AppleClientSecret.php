<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Cache\Repository as Cache;
use Throwable;

/**
 * Apple's "client secret", which is not a secret anyone can paste.
 *
 * Every other provider in the catalogue hands the administrator a string. Apple hands
 * them a downloadable signing key and expects the client secret to be an ES256 JWT
 * minted from it, signed for Apple's audience, valid at most six months. Treating that
 * as a text field is precisely how an Apple integration stops working half a year after
 * the last person touched it, on a day nobody changed anything.
 *
 * So it is minted here, on demand, and cached for a fraction of its life. The lifetime
 * is deliberately short — an hour, not the six months Apple permits — because a minted
 * credential that leaks is only as dangerous as the time it remains valid, and nothing
 * about this flow benefits from a long one.
 *
 * The signing itself goes through firebase/php-jwt, like every other signature in this
 * package. Hand-rolling ES256 means hand-rolling the DER-to-JOSE conversion of the
 * signature, which is exactly the kind of detail that produces a token that works
 * against one implementation and is rejected by another.
 */
class AppleClientSecret
{
    /**
     * One hour. Apple's ceiling is six months; there is no reason to approach it.
     */
    private const TTL_SECONDS = 3600;

    /** Apple requires this exact audience on the client-secret assertion. */
    private const AUDIENCE = 'https://appleid.apple.com';

    public function __construct(private readonly Cache $cache) {}

    /**
     * Mint (or reuse) the client secret for a Sign in with Apple connection.
     *
     * @param  string  $teamId  Apple Developer → Membership
     * @param  string  $keyId  the identifier of the Sign in with Apple key
     * @param  string  $privateKey  the contents of the downloaded .p8 file
     * @param  string  $clientId  the SERVICES id — not the App ID
     *
     * @throws InvalidAssertion when the key will not load or will not sign
     */
    public function mint(string $connectionId, string $teamId, string $keyId, string $privateKey, string $clientId): string
    {
        // Keyed by the connection AND by the material, so rotating the key or correcting
        // a mistyped team id takes effect immediately rather than after the cache
        // expires. Hashed, because the cache key is not a place to put a private key.
        $cacheKey = 'cbox-id:apple-client-secret:'.$connectionId.':'
            .hash('sha256', $teamId."\0".$keyId."\0".$privateKey."\0".$clientId);

        $cached = $this->cache->get($cacheKey);

        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $secret = $this->sign($teamId, $keyId, $privateKey, $clientId);

        // Expire the cache entry BEFORE the token does. An entry that outlived its token
        // would serve an expired credential, and Apple's refusal for that looks exactly
        // like a misconfigured client — sending whoever debugs it to the wrong place.
        $this->cache->put($cacheKey, $secret, self::TTL_SECONDS - 60);

        return $secret;
    }

    private function sign(string $teamId, string $keyId, string $privateKey, string $clientId): string
    {
        $now = time();

        try {
            return JWT::encode(
                [
                    // The team, not the client: Apple identifies the ISSUER of this
                    // assertion as the developer account, and the SUBJECT as the
                    // Services ID acting as the OAuth client.
                    'iss' => $teamId,
                    'iat' => $now,
                    'exp' => $now + self::TTL_SECONDS,
                    'aud' => self::AUDIENCE,
                    'sub' => $clientId,
                ],
                $privateKey,
                'ES256',
                $keyId,
            );
        } catch (Throwable $e) {
            // The overwhelmingly common cause is a .p8 pasted with its newlines eaten by
            // a form field, which openssl reports as an unhelpful parse failure. Say
            // what it usually is, without echoing any of the key material.
            throw InvalidAssertion::make(
                'could not sign the Apple client secret — check that the .p8 key was pasted whole, including its BEGIN and END lines: '.$e->getMessage()
            );
        }
    }
}
