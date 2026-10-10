<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\ValueObjects;

use Cbox\Id\Otp\Sms\Contracts\SmsSender;

/**
 * One text message for a {@see SmsSender}: an E.164 recipient and the body.
 *
 * The body of a one-time-code message carries the code. A sender hands it to its
 * provider and drops it — never logs it at a durable level, never stores it.
 */
readonly class SmsMessage
{
    public function __construct(
        public PhoneNumber $to,
        public string $body,
    ) {}
}
