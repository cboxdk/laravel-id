<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Exceptions;

use RuntimeException;

class DecryptionFailed extends RuntimeException
{
    public static function malformed(): self
    {
        return new self('The ciphertext is malformed or truncated.');
    }

    /**
     * The envelope names the key generation that sealed it, and that generation is not
     * configured — the fix is configuration, so the message says which.
     */
    public static function unknownKey(string $keyId): self
    {
        return new self(
            "The ciphertext was sealed under master key {$keyId}, which is not configured. "
            .'Add that key to CBOX_ID_CRYPTO_PREVIOUS_KEYS (or restore it as CBOX_ID_CRYPTO_KEY).'
        );
    }

    public static function unsupportedVersion(): self
    {
        return new self('The ciphertext uses an envelope version this release does not understand.');
    }

    public static function forContext(): self
    {
        return new self('Decryption failed: wrong key, tampered ciphertext, or mismatched context.');
    }
}
