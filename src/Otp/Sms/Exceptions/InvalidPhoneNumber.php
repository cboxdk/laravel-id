<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Exceptions;

use InvalidArgumentException;

/**
 * The input is not a phone number the platform will text.
 *
 * The message never repeats the input: it is user-typed, often PII, and exceptions end up
 * in logs and error trackers.
 */
class InvalidPhoneNumber extends InvalidArgumentException
{
    public static function malformed(): self
    {
        return new self('The phone number is not in a recognised format. Use international format, e.g. +45 12 34 56 78.');
    }

    public static function unknownCountry(): self
    {
        return new self('The phone number does not belong to a country we can send text messages to.');
    }

    public static function wrongLength(): self
    {
        return new self('The phone number has the wrong number of digits for its country.');
    }

    public static function needsCountry(): self
    {
        return new self('The phone number has no country code. Start it with + and the country code.');
    }
}
