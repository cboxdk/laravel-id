<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\ValueObjects;

use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Enums\OtpFailureReason;

/**
 * The outcome of {@see OtpService::verify()}. A failure
 * carries only a coarse {@see OtpFailureReason} — never a hint about which
 * recipients or challenges exist (see the enum's note).
 */
readonly class OtpResult
{
    private function __construct(
        public bool $verified,
        public OtpFailureReason $reason,
        public ?string $challengeId = null,
    ) {}

    public static function verified(string $challengeId): self
    {
        return new self(true, OtpFailureReason::None, $challengeId);
    }

    public static function invalid(): self
    {
        return new self(false, OtpFailureReason::Invalid);
    }

    public static function expired(string $challengeId): self
    {
        return new self(false, OtpFailureReason::Expired, $challengeId);
    }

    public static function locked(string $challengeId): self
    {
        return new self(false, OtpFailureReason::Locked, $challengeId);
    }

    public static function rateLimited(): self
    {
        return new self(false, OtpFailureReason::RateLimited);
    }

    public function failed(): bool
    {
        return ! $this->verified;
    }
}
