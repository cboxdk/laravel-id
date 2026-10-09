<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Contracts;

use Cbox\Id\Otp\Channels\EmailOtpChannel;
use Cbox\Id\Otp\Channels\LogOtpChannel;
use Cbox\Id\Otp\Channels\NullOtpChannel;
use Cbox\Id\Otp\Channels\SmsOtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;

/**
 * A concrete transport that delivers a one-time passcode to a recipient — email,
 * SMS, push, voice, … The OTP module ships {@see EmailOtpChannel}
 * (over the framework mailer), {@see SmsOtpChannel} (over the SMS drivers, behind the
 * toll-fraud guard — see docs/cookbook/add-an-sms-otp-channel.md), a
 * {@see LogOtpChannel} and a {@see NullOtpChannel} for local dev/tests. A host with its
 * own transport registers its own channel; no provider SDK is a dependency.
 *
 * A channel receives the plaintext code exactly once, at delivery time. It MUST
 * NOT persist, log at a durable level, or echo the code anywhere it would outlive
 * the message.
 */
interface OtpChannel
{
    public function deliver(OtpDelivery $delivery): void;
}
