<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Channels;

use Cbox\Id\Otp\Contracts\OtpChannel;
use Cbox\Id\Otp\Exceptions\UnknownOtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpDelivery;

/**
 * Discards the code — a deliberately-registered black hole for tests and dev
 * environments that exercise issuance without any delivery side effect.
 *
 * This is NOT the deny-by-default behaviour: an UNREGISTERED channel key is
 * refused ({@see UnknownOtpChannel}). NullOtpChannel is a
 * channel a host must opt into explicitly, so "no code was sent" is always a
 * choice, never an accident.
 */
class NullOtpChannel implements OtpChannel
{
    public function deliver(OtpDelivery $delivery): void
    {
        // Intentionally nothing.
    }
}
