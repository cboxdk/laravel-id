<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\ValueObjects;

/**
 * What a provider said when it accepted a message: which provider, and its message id
 * when it returned one (for matching a delivery report or a support ticket later).
 *
 * "Accepted" is all it means. A provider that took the message may still fail to deliver
 * it; delivery reports are a provider-side feature this package does not consume.
 */
readonly class SmsReceipt
{
    public function __construct(
        public string $provider,
        public ?string $messageId = null,
    ) {}
}
