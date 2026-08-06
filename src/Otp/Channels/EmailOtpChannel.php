<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Channels;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;
use Illuminate\Contracts\Mail\Mailer;
use Illuminate\Mail\Message;

/**
 * Delivers a code as a plain-text email over the framework mailer (the host's
 * configured transport). It depends only on the {@see Mailer} CONTRACT, so it
 * adds no dependency and forces no mail transport on a host that only uses SMS.
 *
 * The message is a short, honest verification email — no marketing, no tracking,
 * and the code appears only in the body of this one message.
 */
class EmailOtpChannel implements OtpChannel
{
    public function __construct(
        private readonly Mailer $mailer,
        private readonly string $subject = 'Your verification code',
        private readonly ?string $fromAddress = null,
        private readonly ?string $fromName = null,
    ) {}

    public function deliver(OtpDelivery $delivery): void
    {
        $body = sprintf(
            "Your verification code is: %s\n\n".
            "It expires in %d minute(s) and can be used once.\n\n".
            'If you did not request this code, you can ignore this email.',
            $delivery->code,
            $delivery->ttlMinutes(),
        );

        $this->mailer->raw($body, function (Message $message) use ($delivery): void {
            $message->to($delivery->recipient)->subject($this->subject);

            if ($this->fromAddress !== null && $this->fromAddress !== '') {
                $message->from($this->fromAddress, $this->fromName);
            }
        });
    }
}
