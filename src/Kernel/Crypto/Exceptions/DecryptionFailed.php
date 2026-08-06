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

    public static function forContext(): self
    {
        return new self('Decryption failed: wrong key, tampered ciphertext, or mismatched context.');
    }
}
