<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\LogoutDeliveryStatus;

/**
 * The result of one delivery attempt, with the reason an operator will want when it
 * failed — "HTTP 400: invalid_request", "refused by the SSRF guard: …".
 */
readonly class LogoutDeliveryOutcome
{
    public function __construct(
        public LogoutDeliveryStatus $status,
        public string $reason = '',
        public ?int $httpStatus = null,
    ) {}

    public static function delivered(int $httpStatus): self
    {
        return new self(LogoutDeliveryStatus::Delivered, '', $httpStatus);
    }

    public static function retry(string $reason, ?int $httpStatus = null): self
    {
        return new self(LogoutDeliveryStatus::Retry, $reason, $httpStatus);
    }

    public static function rejected(string $reason, ?int $httpStatus = null): self
    {
        return new self(LogoutDeliveryStatus::Rejected, $reason, $httpStatus);
    }

    public static function skipped(string $reason): self
    {
        return new self(LogoutDeliveryStatus::Skipped, $reason);
    }
}
