<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Channels;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\Sms\Exceptions\InvalidPhoneNumber;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;
use Cbox\Id\Otp\Sms\SmsDispatcher;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;

/**
 * Delivers a code by text to the recipient, which is a phone number in international
 * format (`+4512345678`; formatting is tolerated and stripped).
 *
 * Opt in by mapping it under `cbox-id.otp.channels` (`'sms' => SmsOtpChannel::class`),
 * then issue with `channel: 'sms'`. The provider is `cbox-id.sms.driver`; the toll-fraud
 * controls (`cbox-id.sms.allowed_countries` and the caps under `cbox-id.sms.limits`) apply
 * to every send.
 *
 * Note what the OTP module stores for a challenge sent this way: the recipient — here a
 * phone number — in `otp_challenges.recipient`, as it stores an email address for the
 * email channel. The SMS SECOND FACTOR does not go through this channel for exactly that
 * reason; it sends through its own channel keyed by the factor, so the number exists only
 * sealed.
 */
class SmsOtpChannel implements OtpChannel
{
    public function __construct(
        private readonly PhoneNumberNormaliser $numbers,
        private readonly SmsDispatcher $dispatcher,
    ) {}

    /**
     * @throws InvalidPhoneNumber
     * @throws SmsSendRefused
     * @throws SmsDeliveryFailed
     */
    public function deliver(OtpDelivery $delivery): void
    {
        $this->dispatcher->sendCode($this->numbers->parse($delivery->recipient), $delivery);
    }
}
