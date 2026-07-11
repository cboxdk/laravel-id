<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Exceptions;

use RuntimeException;

final class CryptoConfigurationException extends RuntimeException
{
    public static function missingKey(): self
    {
        return new self(
            'The crypto master key is not configured. Set CBOX_ID_CRYPTO_KEY to a base64-encoded '
            .'32-byte key (e.g. `php -r "echo base64_encode(random_bytes(32));"`).'
        );
    }

    public static function invalidKeyLength(int $expected, int $actual): self
    {
        return new self("The crypto master key must be exactly {$expected} bytes; got {$actual}.");
    }

    public static function keyGenerationFailed(string $reason): self
    {
        return new self('Failed to generate a signing key: '.$reason);
    }
}
