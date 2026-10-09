<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\SmsFactorPolicies;
use Cbox\Id\Identity\Contracts\SmsFactors;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\SmsDispatcher;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;

/**
 * The OTP channel behind the SMS second factor (key {@see SmsFactors::CHANNEL}).
 *
 * Its recipient is a FACTOR (`mfa-sms:{id}`), not a number: the number is opened from
 * its seal here, at the moment of sending, and handed to the dispatcher — so the OTP
 * module never sees it, and nothing it writes contains it.
 *
 * The environment's country allow-list is applied again at send time, not only at
 * enrolment: narrowing the list stops texts to the removed countries immediately, for
 * numbers already enrolled. A disabled policy admits no country at all.
 */
class SmsFactorOtpChannel implements OtpChannel
{
    public function __construct(
        private readonly SmsFactorNumbers $numbers,
        private readonly SmsFactorPolicies $policies,
        private readonly SmsDispatcher $dispatcher,
    ) {}

    public function deliver(OtpDelivery $delivery): void
    {
        $id = SmsFactorNumbers::factorIdFrom($delivery->recipient);

        // Environment-scoped lookup: a factor id from another environment is not found.
        $factor = $id === null ? null : MfaFactor::query()->whereKey($id)->where('type', 'sms')->first();

        if ($factor === null) {
            throw SmsDeliveryFailed::unknownRecipient();
        }

        $policy = $this->policies->forEnvironment();

        $this->dispatcher->sendCode(
            $this->numbers->open($factor),
            $delivery,
            $policy->enabled ? $policy->allowedCountries : [],
        );
    }
}
