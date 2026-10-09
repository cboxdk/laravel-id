<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Senders;

use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\ValueObjects\SmsMessage;
use Cbox\Id\Otp\Sms\ValueObjects\SmsReceipt;
use PHPUnit\Framework\Assert;

/**
 * Keeps every message in memory — the `array` driver, and the fake behind
 * `InteractsWithSms::fakeSms()`. The one place a test legitimately reads a code back.
 *
 * `failNext()` makes the next send throw as a provider refusal would, so a test can prove
 * a flow survives an outage without a real one.
 */
class ArraySmsSender implements SmsSender
{
    /** @var list<SmsMessage> */
    public array $messages = [];

    private bool $failNext = false;

    public function send(SmsMessage $message): SmsReceipt
    {
        if ($this->failNext) {
            $this->failNext = false;

            throw SmsDeliveryFailed::rejected($this->name(), 503);
        }

        $this->messages[] = $message;

        return new SmsReceipt($this->name(), 'array-'.count($this->messages));
    }

    public function name(): string
    {
        return 'array';
    }

    public function failNext(): void
    {
        $this->failNext = true;
    }

    /** The newest message, optionally to one E.164 number. */
    public function latest(?string $to = null): ?SmsMessage
    {
        foreach (array_reverse($this->messages) as $message) {
            if ($to === null || $message->to->e164() === $to) {
                return $message;
            }
        }

        return null;
    }

    /** The code in the newest message (its first run of 6–10 digits). */
    public function latestCode(?string $to = null): ?string
    {
        $message = $this->latest($to);

        if ($message === null || preg_match('/\b(\d{6,10})\b/', $message->body, $match) !== 1) {
            return null;
        }

        return $match[1];
    }

    public function assertSent(?string $to = null): void
    {
        Assert::assertNotNull($this->latest($to), 'Expected a text message'.($to !== null ? " to [{$to}]" : '').', but none was sent.');
    }

    public function assertNothingSent(): void
    {
        Assert::assertSame([], $this->messages, 'Expected no text messages.');
    }

    public function assertSentCount(int $count): void
    {
        Assert::assertCount($count, $this->messages);
    }
}
