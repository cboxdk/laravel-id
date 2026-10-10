<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Exceptions;

use Cbox\Id\Otp\Sms\Enums\SmsRefusalReason;
use RuntimeException;

/**
 * The platform declined to send a text — a toll-fraud or anti-abuse control said no
 * before any provider was called, so nothing was charged.
 *
 * Carries the reason and, for a temporary refusal, the seconds until the same request
 * could succeed. Never the number.
 */
class SmsSendRefused extends RuntimeException
{
    public function __construct(
        public readonly SmsRefusalReason $reason,
        public readonly int $retryAfterSeconds = 0,
    ) {
        parent::__construct(match ($reason) {
            SmsRefusalReason::CountryNotAllowed => 'Text messages cannot be sent to this country.',
            SmsRefusalReason::Cooldown => 'A code was just sent to this number. Wait a moment before asking again.',
            SmsRefusalReason::NumberLimit => 'Too many codes have been sent to this number today.',
            SmsRefusalReason::IpLimit => 'Too many text messages have been requested from this network.',
            SmsRefusalReason::EnvironmentCap, SmsRefusalReason::DailyCap => 'Text messages are temporarily unavailable.',
        });
    }
}
