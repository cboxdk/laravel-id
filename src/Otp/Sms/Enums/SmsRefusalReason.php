<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Enums;

use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;

/**
 * Why the platform declined to send a text (see {@see SmsSendRefused}). Recorded on the
 * `sms.refused` audit row, so an operator can tell a pumping attempt (a run of
 * `country_not_allowed` against unusual destinations) from a person pressing "resend"
 * too often (`cooldown`).
 */
enum SmsRefusalReason: string
{
    /** The number's country is not on the allow-list. */
    case CountryNotAllowed = 'country_not_allowed';

    /** This number was texted moments ago. */
    case Cooldown = 'cooldown';

    /** This number has had its share of texts for the day. */
    case NumberLimit = 'number_limit';

    /** This IP address has asked for too many texts this hour. */
    case IpLimit = 'ip_limit';

    /** This environment has used its daily budget. */
    case EnvironmentCap = 'environment_cap';

    /** The deployment has used its daily budget — the circuit breaker. */
    case DailyCap = 'daily_cap';

    /** Whether the person can usefully try again later (as opposed to: not to this number). */
    public function isTemporary(): bool
    {
        return $this !== self::CountryNotAllowed;
    }
}
