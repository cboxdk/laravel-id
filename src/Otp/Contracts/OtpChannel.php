<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Contracts;

use Cbox\Id\Otp\Channels\EmailOtpChannel;
use Cbox\Id\Otp\Channels\LogOtpChannel;
use Cbox\Id\Otp\Channels\NullOtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;

/**
 * A concrete transport that delivers a one-time passcode to a recipient — email,
 * SMS, push, voice, … The OTP module ships {@see EmailOtpChannel}
 * (over the framework mailer), a {@see LogOtpChannel} and a
 * {@see NullOtpChannel} for local dev/tests. SMS is a
 * CONTRACT ONLY: a host registers its own channel wrapping its provider's SDK
 * (see docs/cookbook/add-an-sms-otp-channel.md) — this package ships no SMS SDK.
 *
 * A channel receives the plaintext code exactly once, at delivery time. It MUST
 * NOT persist, log at a durable level, or echo the code anywhere it would outlive
 * the message.
 */
interface OtpChannel
{
    public function deliver(OtpDelivery $delivery): void;
}
