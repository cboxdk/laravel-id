<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;

/**
 * Seals and opens the phone number of an SMS factor — the only two places it exists in
 * the clear.
 *
 * Sealed under the SAME context as the person's TOTP secret (`cbox-id:mfa:{user_id}`):
 * both live in `mfa_factors.secret_encrypted`, and that column is registered once for
 * key rotation with exactly that context. Binding to the person means a sealed number
 * copied onto someone else's row does not open.
 *
 * Also how an OTP challenge names an SMS factor: `mfa-sms:{factor id}`, so the challenge
 * table, the `otp.issued` audit row and every rate-limit key carry an opaque id instead
 * of a phone number.
 */
class SmsFactorNumbers
{
    public const RECIPIENT_PREFIX = 'mfa-sms:';

    public function __construct(
        private readonly SecretBox $secretBox,
        private readonly PhoneNumberNormaliser $numbers,
    ) {}

    public function seal(string $userId, PhoneNumber $number): string
    {
        return $this->secretBox->seal($number->e164(), self::context($userId));
    }

    public function open(MfaFactor $factor): PhoneNumber
    {
        return $this->numbers->parse($this->secretBox->open($factor->secret_encrypted, self::context($factor->user_id)));
    }

    public static function recipient(MfaFactor $factor): string
    {
        return self::RECIPIENT_PREFIX.$factor->id;
    }

    /** The factor id a recipient names, or null when it is not an SMS-factor recipient. */
    public static function factorIdFrom(string $recipient): ?string
    {
        if (! str_starts_with($recipient, self::RECIPIENT_PREFIX)) {
            return null;
        }

        $id = substr($recipient, strlen(self::RECIPIENT_PREFIX));

        return $id !== '' ? $id : null;
    }

    private static function context(string $userId): string
    {
        return 'cbox-id:mfa:'.$userId;
    }
}
