<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

/**
 * A freshly generated signing key pair, kept as two NAMED halves.
 *
 * This existed as `array{0: string, 1: string}` — both halves `string`, so
 * transposing them was invisible to the type system, to PHPStan and to a reviewer
 * skimming a diff, while the failure mode was publishing the PRIVATE key at the
 * JWKS endpoint and sealing the public one. Naming the halves makes that
 * transposition unrepresentable: `$pair->publicKey` cannot silently become the
 * private half.
 *
 * Encoding follows the algorithm: PEM for RSA/EC, base64-encoded raw sodium keys
 * for Ed25519 (which is what firebase/php-jwt signs and verifies EdDSA with).
 */
readonly class GeneratedKeyPair
{
    public function __construct(
        public string $publicKey,
        public string $privateKey,
    ) {}
}
