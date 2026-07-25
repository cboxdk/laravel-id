<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Enums;

/**
 * Asymmetric signing algorithms supported for JWT issuance.
 *
 * Deliberately a closed set — no `none`, no symmetric (HS*) algorithms — which
 * structurally rules out `alg=none` and RS↔HS confusion at the type level.
 */
enum SigningAlg: string
{
    case RS256 = 'RS256';
    case ES256 = 'ES256';
    case EdDSA = 'EdDSA';

    public function jwkKeyType(): string
    {
        return match ($this) {
            self::RS256 => 'RSA',
            self::ES256 => 'EC',
            self::EdDSA => 'OKP',
        };
    }

    /**
     * The hash used for the OIDC `at_hash`/`c_hash` half-digests (OIDC Core §3.1.3.6):
     * the hash of the id_token's OWN signing algorithm, not a fixed one. Ed25519 signs
     * over SHA-512, so an EdDSA id_token must carry a SHA-512-derived hash — computing
     * SHA-256 there produces a value a strict relying party rejects.
     */
    public function hashAlgorithm(): string
    {
        return match ($this) {
            self::RS256, self::ES256 => 'sha256',
            self::EdDSA => 'sha512',
        };
    }
}
