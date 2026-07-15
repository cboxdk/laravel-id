<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Contracts;

use Cbox\Id\Otp\Exceptions\UnknownOtpChannel;
use Cbox\Id\Otp\Testing\FakeOtpChannel;

/**
 * Deny-by-default registry of {@see OtpChannel} senders keyed by a short string
 * (`email`, `sms`, `log`, …). A key with no registered sender is REFUSED
 * ({@see UnknownOtpChannel}), never a silent no-op — an
 * unconfigured "text me a code" must fail loudly, not swallow the request while
 * the user waits for a code that never comes.
 */
interface OtpChannels
{
    /**
     * Register (or replace) the sender for a channel key. Used by hosts to wire an
     * SMS provider, and by the test trait to inject a {@see FakeOtpChannel}.
     */
    public function register(string $key, OtpChannel $channel): void;

    public function has(string $key): bool;

    /**
     * @throws UnknownOtpChannel when no sender is registered for `$key`
     */
    public function channel(string $key): OtpChannel;

    /**
     * The registered channel keys.
     *
     * @return list<string>
     */
    public function keys(): array;
}
