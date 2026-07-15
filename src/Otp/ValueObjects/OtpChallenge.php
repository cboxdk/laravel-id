<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\ValueObjects;

use Cbox\Id\Otp\Contracts\OtpService;
use DateTimeImmutable;

/**
 * The caller-facing description of an issued challenge, returned by
 * {@see OtpService::issue()}.
 *
 * It deliberately does NOT carry the plaintext code — the code is delivered only
 * through the channel. The host keeps {@see $id} to later verify, and may show the
 * expiry / attempt budget in its UI.
 */
readonly class OtpChallenge
{
    public function __construct(
        public string $id,
        public string $purpose,
        public string $channel,
        public string $recipient,
        public DateTimeImmutable $expiresAt,
        public int $maxAttempts,
    ) {}
}
