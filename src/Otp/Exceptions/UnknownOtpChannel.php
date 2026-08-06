<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Exceptions;

use RuntimeException;

/**
 * Raised when a channel key has no registered sender. Deny-by-default: the
 * request is refused rather than silently dropped.
 */
class UnknownOtpChannel extends RuntimeException
{
    public static function forKey(string $key): self
    {
        return new self("No OTP channel is registered for key [{$key}].");
    }
}
