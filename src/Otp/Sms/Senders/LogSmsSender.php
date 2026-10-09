<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Cbox\Id\Otp\Sms\ValueObjects\SmsReceipt;
use Psr\Log\LoggerInterface;

/**
 * Writes the message — code included — to the application log, for LOCAL DEVELOPMENT.
 *
 * It is the default driver so a fresh checkout can walk an SMS flow without an account at
 * a provider, and it REFUSES to run when the application environment is `production`: a
 * deployment that turned SMS on and forgot to pick a provider fails loudly at the first
 * send instead of quietly writing every customer's codes to its logs.
 */
class LogSmsSender implements SmsSender
{
    public function __construct(
        private readonly LoggerInterface $log,
        private readonly bool $production,
    ) {}

    public function send(SmsMessage $message): SmsReceipt
    {
        if ($this->production) {
            throw SmsDeliveryFailed::logDriverInProduction();
        }

        $this->log->warning('[sms] dev-only delivery (do NOT use in production)', [
            'to' => $message->to->e164(),
            'body' => $message->body,
        ]);

        return new SmsReceipt($this->name());
    }

    public function name(): string
    {
        return 'log';
    }
}
