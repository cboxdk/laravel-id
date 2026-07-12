<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Contracts;

use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;

/**
 * Manages the platform's asymmetric signing keys and publishes them as JWKS.
 *
 * Private keys are always stored sealed (see {@see SecretBox}) and only ever
 * decrypted in memory at signing time.
 */
interface KeyManager
{
    /**
     * The active signing key for the algorithm, generating one on first use.
     */
    public function activeSigningKey(SigningAlg $alg = SigningAlg::RS256): SigningKey;

    /**
     * Rotate: demote the current active key to `rotating` (still in JWKS so
     * in-flight tokens verify) and generate a new active key.
     */
    public function rotate(SigningAlg $alg = SigningAlg::RS256): SigningKey;

    /**
     * Permanently retire a key by `kid`: it leaves the JWKS and is no longer
     * trusted for verification — the compromise-response revoke. After this,
     * tokens signed by that key are rejected. Idempotent.
     */
    public function retire(string $kid): void;

    /**
     * The public JWK Set (active + rotating keys), for `/.well-known/jwks.json`.
     *
     * @return array{keys: list<array<string, string>>}
     */
    public function jwks(): array;
}
