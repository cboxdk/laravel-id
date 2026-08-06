<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Contracts;

use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;

/**
 * Authenticated envelope encryption for secrets at rest (connection configs,
 * MFA secrets, private signing keys, webhook secrets).
 *
 * The `context` is bound into the ciphertext as additional authenticated data:
 * decryption only succeeds with the exact same context, so a ciphertext sealed
 * for one record cannot be replayed against another.
 */
interface SecretBox
{
    public function seal(string $plaintext, string $context = ''): string;

    /**
     * @throws DecryptionFailed on wrong key, tampered ciphertext, or context mismatch
     */
    public function open(string $ciphertext, string $context = ''): string;
}
