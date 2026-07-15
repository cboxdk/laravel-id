<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Channels;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;
use Psr\Log\LoggerInterface;

/**
 * Writes the code to the application log for LOCAL DEVELOPMENT only. This exists
 * so a developer can read the code off the log without wiring a real transport.
 *
 * NEVER register this channel in production: it deliberately puts the plaintext
 * code in the log, which is exactly what every other part of the module avoids.
 */
class LogOtpChannel implements OtpChannel
{
    public function __construct(private readonly LoggerInterface $log) {}

    public function deliver(OtpDelivery $delivery): void
    {
        $this->log->warning('[otp] dev-only code delivery (do NOT use in production)', [
            'channel' => $delivery->channel,
            'purpose' => $delivery->purpose,
            'recipient' => $delivery->recipient,
            'code' => $delivery->code,
            'expires_at' => $delivery->expiresAt->format(DATE_ATOM),
        ]);
    }
}
