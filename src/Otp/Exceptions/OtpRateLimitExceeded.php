<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Exceptions;

use RuntimeException;

/**
 * Raised when issuing a code exceeds the per-recipient window — the guard against
 * using OTP issuance to bomb a recipient or run up SMS cost. Carries the seconds
 * until the caller may retry; never carries a code.
 */
class OtpRateLimitExceeded extends RuntimeException
{
    public function __construct(public readonly int $retryAfterSeconds)
    {
        parent::__construct('Too many OTP requests for this recipient. Retry later.');
    }
}
