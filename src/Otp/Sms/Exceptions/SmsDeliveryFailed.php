<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Sms\Exceptions;

use RuntimeException;
use Throwable;

/**
 * The provider did not accept the message.
 *
 * The message names the provider and the HTTP status (and the provider's own numeric
 * error code when it sent one) — never the recipient or the body, which carry a phone
 * number and a live code.
 */
class SmsDeliveryFailed extends RuntimeException
{
    public static function rejected(string $provider, int $status, ?string $providerCode = null): self
    {
        $detail = $providerCode !== null && $providerCode !== '' ? ", provider code {$providerCode}" : '';

        return new self("The SMS provider [{$provider}] refused the message (HTTP {$status}{$detail}).");
    }

    public static function unreachable(string $provider, ?Throwable $previous = null): self
    {
        return new self("The SMS provider [{$provider}] could not be reached.", 0, $previous);
    }

    public static function misconfigured(string $provider, string $missing): self
    {
        return new self("The SMS driver [{$provider}] is missing its [{$missing}] setting.");
    }

    public static function unknownDriver(string $driver): self
    {
        return new self("No SMS driver is named [{$driver}].");
    }

    public static function logDriverInProduction(): self
    {
        return new self('The [log] SMS driver writes codes to the log and is refused in production. Configure CBOX_ID_SMS_DRIVER.');
    }

    public static function unknownRecipient(): self
    {
        return new self('The SMS recipient could not be resolved to a phone number.');
    }
}
