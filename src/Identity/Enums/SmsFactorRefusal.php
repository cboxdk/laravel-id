<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Enums;

/**
 * Why the SMS second factor said no — before any text was sent.
 */
enum SmsFactorRefusal: string
{
    /** The environment does not accept SMS as a second factor. */
    case NotEnabled = 'not_enabled';

    /** The number is not one the platform can text. */
    case InvalidNumber = 'invalid_number';

    /** The environment does not accept numbers from this country. */
    case CountryNotAllowed = 'country_not_allowed';

    /** An administrator must hold an authenticator app or a passkey before adding SMS. */
    case StrongerFactorRequired = 'stronger_factor_required';

    /** A confirmed number is already enrolled; remove it first. */
    case AlreadyEnrolled = 'already_enrolled';

    /** No confirmed number to text. */
    case NotEnrolled = 'not_enrolled';
}
