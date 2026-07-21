<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Crypto\ValueObjects\TokenClaims;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Throwable;

/**
 * JWT signer/verifier over the platform's managed keys.
 *
 * Verification builds the candidate key set from ONLY those keys whose algorithm
 * is in the caller's allow-list, and lets the JWT library bind each key to its
 * algorithm. A token asking for `none`, or for an algorithm that isn't allowed,
 * has no matching key and is rejected — the algorithm is never trusted from the
 * token header.
 */
class JwtTokenSigner implements TokenSigner
{
    public function __construct(
        private readonly KeyManager $keys,
        private readonly SecretBox $secretBox,
    ) {}

    public function sign(array $claims, ?SigningAlg $alg = null, ?string $type = null): string
    {
        $signingKey = $this->keys->activeSigningKey($alg ?? SigningAlg::RS256);
        $privatePem = $this->secretBox->open($signingKey->private_key_encrypted, $signingKey->secretContext());

        // Default anti-replay claims when the caller didn't set them: `iat` anchors
        // freshness and `jti` gives every token a unique id. We deliberately do NOT
        // inject `exp` — audit checkpoints are signed with sign() and are meant to
        // never expire, so an expiry is the caller's decision to make explicitly.
        $claims['iat'] ??= time();
        $claims['jti'] ??= bin2hex(random_bytes(16));

        // An explicit `typ` (e.g. `at+jwt`, RFC 9068) lets a resource server reject
        // a token of the wrong type — defeating token-type confusion.
        $head = $type !== null ? ['typ' => $type] : [];

        return JWT::encode($claims, $privatePem, $signingKey->alg->value, $signingKey->kid, $head);
    }

    public function verify(string $jwt, array $allowed): TokenClaims
    {
        return $this->decode($jwt, $allowed, ignoreExpiry: false);
    }

    /**
     * Verify signature + algorithm but NOT `exp` — for cases where the token is used
     * as a proof of IDENTITY, not liveness (e.g. an OIDC `id_token_hint` at logout,
     * which is routinely already expired). Signature/alg pinning is unchanged, so a
     * forged token is still rejected; only the expiry clock is ignored.
     */
    public function verifyIgnoringExpiry(string $jwt, array $allowed): TokenClaims
    {
        return $this->decode($jwt, $allowed, ignoreExpiry: true);
    }

    /**
     * @param  list<SigningAlg>  $allowed
     *
     * @throws InvalidToken
     */
    private function decode(string $jwt, array $allowed, bool $ignoreExpiry): TokenClaims
    {
        if ($allowed === []) {
            throw InvalidToken::emptyAllowList();
        }

        $allowedValues = array_map(static fn (SigningAlg $alg): string => $alg->value, $allowed);

        $keySet = [];
        foreach ($this->keys->verificationKeys() as $candidate) {
            if (in_array($candidate->alg->value, $allowedValues, true)) {
                $keySet[$candidate->kid] = new Key($candidate->publicKey, $candidate->alg->value);
            }
        }

        if ($keySet === []) {
            throw InvalidToken::noVerificationKeys();
        }

        // firebase has no per-call "ignore exp" flag — only the static leeway. Set it
        // wide enough to cover any expiry, then restore it in `finally` so the global
        // is never left mutated (signature verification is unaffected by leeway).
        $previousLeeway = JWT::$leeway;
        if ($ignoreExpiry) {
            JWT::$leeway = 315_360_000; // ~10 years
        }

        try {
            $decoded = JWT::decode($jwt, $keySet);
        } catch (Throwable $exception) {
            throw InvalidToken::verificationFailed($exception->getMessage());
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        // JWT payload keys are always strings (JSON object members).
        $claims = [];
        foreach (get_object_vars($decoded) as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return new TokenClaims($claims);
    }
}
