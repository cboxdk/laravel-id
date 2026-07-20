<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Exceptions;

use RuntimeException;

class InvalidToken extends RuntimeException
{
    public static function verificationFailed(string $reason): self
    {
        return new self('Token verification failed: '.$reason);
    }

    public static function noVerificationKeys(): self
    {
        return new self('No verification key is available for any of the allowed algorithms.');
    }

    public static function emptyAllowList(): self
    {
        return new self('At least one allowed algorithm must be supplied when verifying a token.');
    }
}
