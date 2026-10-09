<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Contracts;

use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\Senders\ArraySmsSender;
use Cbox\Id\Otp\Sms\Senders\BirdSmsSender;
use Cbox\Id\Otp\Sms\Senders\FortySixElksSmsSender;
use Cbox\Id\Otp\Sms\Senders\LogSmsSender;
use Cbox\Id\Otp\Sms\Senders\MessageBirdSmsSender;
use Cbox\Id\Otp\Sms\Senders\TwilioSmsSender;
use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Cbox\Id\Otp\Sms\ValueObjects\SmsReceipt;

/**
 * The transport under every SMS the platform sends: hand one message to a provider.
 *
 * Shipped drivers, selected by `cbox-id.sms.driver`: {@see TwilioSmsSender} (`twilio`),
 * {@see MessageBirdSmsSender} (`messagebird`, the legacy REST API), {@see BirdSmsSender}
 * (`bird`, the Channels API), {@see FortySixElksSmsSender} (`46elks`), {@see LogSmsSender}
 * (`log`, local development; refuses in production) and {@see ArraySmsSender} (`array`,
 * tests). Each talks HTTP through Laravel's client — no provider SDK is a dependency.
 *
 * A sender does transport and nothing else. Who may be texted, how often, and in which
 * country is decided BEFORE it is called (see `SmsSendGuard`), so a host's own sender
 * inherits every toll-fraud control without implementing any.
 */
interface SmsSender
{
    /**
     * @throws SmsDeliveryFailed when the provider refuses the message or cannot be reached
     */
    public function send(SmsMessage $message): SmsReceipt;

    /** The driver name recorded on the audit row (`twilio`, `46elks`, …). */
    public function name(): string;
}
