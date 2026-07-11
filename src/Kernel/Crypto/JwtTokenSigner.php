<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Exceptions\InvalidToken;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
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
final class JwtTokenSigner implements TokenSigner
{
    public function __construct(
        private readonly KeyManager $keys,
        private readonly SecretBox $secretBox,
    ) {}

    public function sign(array $claims, ?SigningAlg $alg = null): string
    {
        $signingKey = $this->keys->activeSigningKey($alg ?? SigningAlg::RS256);
        $privatePem = $this->secretBox->open($signingKey->private_key_encrypted, $signingKey->secretContext());

        return JWT::encode($claims, $privatePem, $signingKey->alg->value, $signingKey->kid);
    }

    public function verify(string $jwt, array $allowed): TokenClaims
    {
        if ($allowed === []) {
            throw InvalidToken::emptyAllowList();
        }

        $allowedValues = array_map(static fn (SigningAlg $alg): string => $alg->value, $allowed);

        $candidates = SigningKey::query()
            ->whereIn('status', [KeyStatus::Active->value, KeyStatus::Rotating->value])
            ->whereIn('alg', $allowedValues)
            ->get();

        if ($candidates->isEmpty()) {
            throw InvalidToken::noVerificationKeys();
        }

        $keySet = [];
        foreach ($candidates as $candidate) {
            $keySet[$candidate->kid] = new Key($candidate->public_key, $candidate->alg->value);
        }

        try {
            $decoded = JWT::decode($jwt, $keySet);
        } catch (Throwable $exception) {
            throw InvalidToken::verificationFailed($exception->getMessage());
        }

        // JWT payload keys are always strings (JSON object members).
        $claims = [];
        foreach (get_object_vars($decoded) as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return new TokenClaims($claims);
    }
}
