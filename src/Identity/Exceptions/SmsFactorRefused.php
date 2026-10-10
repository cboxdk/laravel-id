<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use Cbox\Id\Identity\Enums\SmsFactorRefusal;
use RuntimeException;

/**
 * The SMS second factor refused a request on policy grounds. Nothing was sent and nothing
 * was stored. The message is safe to show; it never contains the number.
 */
class SmsFactorRefused extends RuntimeException
{
    public function __construct(public readonly SmsFactorRefusal $reason)
    {
        parent::__construct(match ($reason) {
            SmsFactorRefusal::NotEnabled => 'Text-message codes are not available here.',
            SmsFactorRefusal::InvalidNumber => 'That is not a phone number we can send a text message to.',
            SmsFactorRefusal::CountryNotAllowed => 'Text messages cannot be sent to numbers in that country.',
            SmsFactorRefusal::StrongerFactorRequired => 'Administrators must set up an authenticator app or a passkey before adding a phone number.',
            SmsFactorRefusal::AlreadyEnrolled => 'A phone number is already set up. Remove it before adding another.',
            SmsFactorRefusal::NotEnrolled => 'No phone number is set up for text-message codes.',
        });
    }
}
