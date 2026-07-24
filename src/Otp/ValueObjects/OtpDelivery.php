<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\ValueObjects;

use Cbox\Id\Otp\Contracts\OtpChannel;
use DateTimeImmutable;

/**
 * Everything a {@see OtpChannel} needs to deliver one code.
 *
 * This is the ONLY place the plaintext code travels after generation; it is passed
 * to the channel and then discarded. The channel must not persist or log it.
 */
readonly class OtpDelivery
{
    public function __construct(
        public string $challengeId,
        public string $recipient,
        public string $code,
        public string $purpose,
        public string $channel,
        public DateTimeImmutable $expiresAt,
        public int $ttlSeconds,
    ) {}

    /**
     * Whole minutes until expiry, rounded up — for a human-readable "expires in N
     * minutes" line. Never below 1.
     */
    public function ttlMinutes(): int
    {
        return max(1, (int) ceil($this->ttlSeconds / 60));
    }
}
