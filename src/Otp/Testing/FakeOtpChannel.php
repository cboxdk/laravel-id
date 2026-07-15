<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Testing;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;
use PHPUnit\Framework\Assert;

/**
 * In-memory {@see OtpChannel} for tests: captures every delivery so a test can
 * read back the code that would have been sent, in the spirit of Laravel's
 * `Mail::fake()`. This is the one place a test legitimately sees the plaintext
 * code — it never leaves the process.
 */
class FakeOtpChannel implements OtpChannel
{
    /**
     * @var list<OtpDelivery>
     */
    public array $deliveries = [];

    public function deliver(OtpDelivery $delivery): void
    {
        $this->deliveries[] = $delivery;
    }

    public function latest(): ?OtpDelivery
    {
        return $this->deliveries === [] ? null : $this->deliveries[array_key_last($this->deliveries)];
    }

    /**
     * The code most recently delivered to `$recipient` (or the very latest when no
     * recipient is given).
     */
    public function codeFor(?string $recipient = null): ?string
    {
        foreach (array_reverse($this->deliveries) as $delivery) {
            if ($recipient === null || $delivery->recipient === $recipient) {
                return $delivery->code;
            }
        }

        return null;
    }

    public function assertDelivered(?string $recipient = null): void
    {
        $match = $recipient === null
            ? $this->deliveries !== []
            : array_filter($this->deliveries, fn (OtpDelivery $d): bool => $d->recipient === $recipient) !== [];

        Assert::assertTrue($match, 'Expected an OTP to have been delivered'.($recipient !== null ? " to [{$recipient}]" : '').', but none was.');
    }

    public function assertNothingDelivered(): void
    {
        Assert::assertSame([], $this->deliveries, 'Expected no OTP deliveries.');
    }

    public function assertDeliveredCount(int $count): void
    {
        Assert::assertCount($count, $this->deliveries);
    }
}
