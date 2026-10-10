<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\PrivilegedSubjects;
use Cbox\Id\Identity\Contracts\SmsFactorPolicies;
use Cbox\Id\Identity\Contracts\SmsFactors;
use Cbox\Id\Identity\Enums\SmsFactorRefusal;
use Cbox\Id\Identity\Exceptions\SmsFactorRefused;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\SmsCodeSent;
use Cbox\Id\Identity\ValueObjects\SmsFactorDetails;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Sms\Exceptions\InvalidPhoneNumber;
use Cbox\Id\Otp\Sms\PhoneNumberNormaliser;
use Cbox\Id\Otp\Sms\ValueObjects\PhoneNumber;
use Illuminate\Support\Traits\Localizable;

/**
 * The default {@see SmsFactors}. See the contract for the guarantees; the shape of the
 * implementation:
 *
 *  - The factor is an `mfa_factors` row of type `sms` (one per person, the table's unique
 *    key), its number sealed by {@see SmsFactorNumbers}. Unconfirmed until the texted
 *    code is proven, exactly like a TOTP enrolment.
 *  - Codes are OTP challenges over the {@see SmsFactorOtpChannel}, addressed to the
 *    factor; enrolment and sign-in use different purposes so a code for one cannot be
 *    spent on the other. Length, lifetime, attempts and verify throttles are the OTP
 *    module's (`cbox-id.otp.*`), the send caps the SMS guard's (`cbox-id.sms.limits`).
 *  - The policy is read on EVERY call. Turning SMS off, or dropping a country, takes
 *    effect on the next request for everyone already enrolled.
 */
class SmsFactorService implements SmsFactors
{
    use Localizable;

    private const TYPE = 'sms';

    public function __construct(
        private readonly SmsFactorPolicies $policies,
        private readonly PrivilegedSubjects $privileged,
        private readonly Mfa $mfa,
        private readonly OtpService $otp,
        private readonly SmsFactorNumbers $sealed,
        private readonly PhoneNumberNormaliser $numbers,
        private readonly AuditLog $audit,
    ) {}

    public function beginEnrolment(string $userId, string $phoneNumber, ?string $defaultCountry = null, ?string $ip = null, ?string $locale = null): SmsCodeSent
    {
        $policy = $this->policies->forEnvironment();

        if (! $policy->enabled) {
            throw new SmsFactorRefused(SmsFactorRefusal::NotEnabled);
        }

        try {
            $number = $this->numbers->parse($phoneNumber, $defaultCountry);
        } catch (InvalidPhoneNumber) {
            throw new SmsFactorRefused(SmsFactorRefusal::InvalidNumber);
        }

        if (! $policy->allowsCountry($number->country)) {
            throw new SmsFactorRefused(SmsFactorRefusal::CountryNotAllowed);
        }

        // Checked at ENROLMENT so an administrator never ends up holding SMS alone by their
        // own choice. Becoming an administrator later is caught by needsStrongerFactor().
        if ($policy->privilegedNeedStrongerFactor
            && ! $this->hasStrongerFactor($userId)
            && $this->privileged->isPrivileged($userId)) {
            throw new SmsFactorRefused(SmsFactorRefusal::StrongerFactorRequired);
        }

        $pending = $this->factor($userId);

        if ($pending?->confirmed_at !== null) {
            throw new SmsFactorRefused(SmsFactorRefusal::AlreadyEnrolled);
        }

        // A NEW row, never the old one updated: codes are addressed to the factor's id, so
        // reusing it would let the code texted to an abandoned number confirm the new one —
        // a number nobody proved they hold.
        $pending?->delete();

        $factor = MfaFactor::query()->create([
            'user_id' => $userId,
            'type' => self::TYPE,
            'secret_encrypted' => $this->sealed->seal($userId, $number),
        ]);

        return $this->send(self::PURPOSE_ENROL, $factor, $number, $ip, $locale);
    }

    public function confirmEnrolment(string $userId, string $code, ?string $ip = null): bool
    {
        $factor = $this->factor($userId);

        if ($factor === null || $factor->confirmed_at !== null || ! $this->policies->forEnvironment()->enabled) {
            return false;
        }

        if (! $this->otp->verifyLatest(self::PURPOSE_ENROL, SmsFactorNumbers::recipient($factor), $code, $ip)->verified) {
            return false;
        }

        $factor->forceFill(['confirmed_at' => now()])->save();

        $this->audit->record(new AuditEvent(
            action: 'user.mfa_enrolled',
            actorType: ActorType::User,
            actorId: $userId,
            targetType: 'user',
            targetId: $userId,
            context: ['type' => self::TYPE, 'country' => $this->sealed->open($factor)->country],
            ip: $ip,
        ));

        return true;
    }

    public function sendChallenge(string $userId, ?string $ip = null, ?string $locale = null): SmsCodeSent
    {
        $factor = $this->confirmedFactor($userId);

        if ($factor === null) {
            throw new SmsFactorRefused(SmsFactorRefusal::NotEnrolled);
        }

        $policy = $this->policies->forEnvironment();

        if (! $policy->enabled) {
            throw new SmsFactorRefused(SmsFactorRefusal::NotEnabled);
        }

        $number = $this->sealed->open($factor);

        if (! $policy->allowsCountry($number->country)) {
            throw new SmsFactorRefused(SmsFactorRefusal::CountryNotAllowed);
        }

        return $this->send(self::PURPOSE_CHALLENGE, $factor, $number, $ip, $locale);
    }

    public function verifyChallenge(string $userId, string $code, ?string $ip = null): bool
    {
        $factor = $this->confirmedFactor($userId);

        // A factor the policy no longer accepts cannot complete a sign-in, even with a code
        // texted before the policy changed.
        if ($factor === null || ! $this->usable($factor)) {
            return false;
        }

        return $this->otp->verifyLatest(self::PURPOSE_CHALLENGE, SmsFactorNumbers::recipient($factor), $code, $ip)->verified;
    }

    public function isEnrolled(string $userId): bool
    {
        return $this->confirmedFactor($userId) !== null;
    }

    public function isUsable(string $userId): bool
    {
        $factor = $this->confirmedFactor($userId);

        return $factor !== null && $this->usable($factor);
    }

    public function needsStrongerFactor(string $userId): bool
    {
        if (! $this->policies->forEnvironment()->privilegedNeedStrongerFactor || ! $this->isUsable($userId)) {
            return false;
        }

        return ! $this->hasStrongerFactor($userId) && $this->privileged->isPrivileged($userId);
    }

    public function details(string $userId): ?SmsFactorDetails
    {
        $factor = $this->factor($userId);

        if ($factor === null) {
            return null;
        }

        $number = $this->sealed->open($factor);

        return new SmsFactorDetails(
            maskedNumber: $number->masked(),
            country: $number->country,
            confirmed: $factor->confirmed_at !== null,
            confirmedAt: $factor->confirmed_at?->toDateTimeImmutable(),
        );
    }

    public function remove(string $userId, ?ActorType $actorType = null, ?string $actorId = null): bool
    {
        $deleted = MfaFactor::query()->where('user_id', $userId)->where('type', self::TYPE)->delete();

        if ($deleted === 0) {
            return false;
        }

        $this->audit->record(new AuditEvent(
            action: 'user.mfa_sms_removed',
            actorType: $actorType ?? ActorType::User,
            actorId: $actorId ?? $userId,
            targetType: 'user',
            targetId: $userId,
        ));

        return true;
    }

    /**
     * Issue the code in the recipient's language: the OTP module stamps the delivery with
     * the current locale, so a caller texting on someone's behalf (a console, a queue
     * job) passes theirs and it applies to this one send only.
     */
    private function send(string $purpose, MfaFactor $factor, PhoneNumber $number, ?string $ip, ?string $locale): SmsCodeSent
    {
        $challenge = $this->withLocale(
            $locale ?? app()->getLocale(),
            fn () => $this->otp->issue($purpose, SmsFactorNumbers::recipient($factor), self::CHANNEL, $ip),
        );

        return new SmsCodeSent($challenge->id, $number->masked(), $challenge->expiresAt);
    }

    private function usable(MfaFactor $factor): bool
    {
        return $this->policies->forEnvironment()->allowsCountry($this->sealed->open($factor)->country);
    }

    /** An authenticator app or a passkey — the factors that do not ride on a phone number. */
    private function hasStrongerFactor(string $userId): bool
    {
        return $this->mfa->hasConfirmedTotp($userId)
            || WebAuthnCredential::query()->where('user_id', $userId)->exists();
    }

    private function factor(string $userId): ?MfaFactor
    {
        return MfaFactor::query()->where('user_id', $userId)->where('type', self::TYPE)->first();
    }

    private function confirmedFactor(string $userId): ?MfaFactor
    {
        return MfaFactor::query()->where('user_id', $userId)->where('type', self::TYPE)->whereNotNull('confirmed_at')->first();
    }
}
