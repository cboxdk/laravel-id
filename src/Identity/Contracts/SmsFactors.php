<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\SmsFactorRefused;
use Cbox\Id\Identity\ValueObjects\SmsCodeSent;
use Cbox\Id\Identity\ValueObjects\SmsFactorDetails;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Otp\Exceptions\OtpRateLimitExceeded;
use Cbox\Id\Otp\Sms\Exceptions\SmsDeliveryFailed;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;

/**
 * A phone number as a second factor: enrol it (prove it with a texted code), challenge
 * with it at sign-in, remove it.
 *
 * Built on the OTP module, so code length, lifetime, attempt cap, hashing and the verify
 * throttles are exactly those of an emailed code — and on the SMS dispatcher, so every
 * text passes the toll-fraud guard and is audited with the number masked.
 *
 * THE NUMBER IS STORED SEALED (the SecretBox, bound to the person) in `mfa_factors`, as a
 * factor of type `sms`, and is opened only to send a text. The OTP challenge rows name the
 * FACTOR, not the number, so no table holds it in the clear.
 *
 * Gated by the environment's {@see SmsFactorPolicies} on every call — off by default — so
 * an environment that turns SMS off stops it being used at once; a person whose only
 * factor was SMS is then treated as having none (and the MFA mandate, if any, asks them
 * to enrol another).
 *
 * Recovery codes are separate ({@see Mfa}) and unaffected by anything here.
 */
interface SmsFactors
{
    /** The channel key the factor's codes are sent through. */
    public const CHANNEL = 'sms_factor';

    /** OTP purposes, so an enrolment code cannot complete a sign-in or the reverse. */
    public const PURPOSE_ENROL = 'mfa_sms_enrol';

    public const PURPOSE_CHALLENGE = 'mfa_sms';

    /**
     * Start enrolling `$phoneNumber`: check the policy, store the number sealed and
     * UNCONFIRMED, and text it a code. Starting again replaces an unconfirmed number.
     *
     * @param  string|null  $defaultCountry  ISO country for a number typed without a country code
     * @param  string|null  $locale  the language the text is written in (default: the current locale)
     *
     * @throws SmsFactorRefused on policy grounds (nothing stored, nothing sent)
     * @throws OtpRateLimitExceeded|SmsSendRefused when an issue or send cap refuses
     * @throws SmsDeliveryFailed when the provider does not take the message
     */
    public function beginEnrolment(string $userId, string $phoneNumber, ?string $defaultCountry = null, ?string $ip = null, ?string $locale = null): SmsCodeSent;

    /** Prove the number with the texted code. True marks the factor confirmed. */
    public function confirmEnrolment(string $userId, string $code, ?string $ip = null): bool;

    /**
     * Text a sign-in code to the person's confirmed number.
     *
     * @throws SmsFactorRefused when there is no usable number
     * @throws OtpRateLimitExceeded|SmsSendRefused|SmsDeliveryFailed
     */
    public function sendChallenge(string $userId, ?string $ip = null, ?string $locale = null): SmsCodeSent;

    /** Check a sign-in code. Single use; false for wrong, expired, or not usable. */
    public function verifyChallenge(string $userId, string $code, ?string $ip = null): bool;

    /** A confirmed number is on file — whether or not the policy accepts it right now. */
    public function isEnrolled(string $userId): bool;

    /** A confirmed number is on file AND the environment accepts it now (enabled, country). */
    public function isUsable(string $userId): bool;

    /**
     * The person is an administrator, the policy says SMS cannot be an administrator's
     * only factor, and SMS is all they have. They can still sign in with it — refusing
     * would leave a password alone, which is worse — but the MFA mandate asks them to
     * enrol an authenticator app or a passkey.
     */
    public function needsStrongerFactor(string $userId): bool;

    /** The masked number and its state, or null when none is on file. */
    public function details(string $userId): ?SmsFactorDetails;

    /**
     * Remove the person's SMS factor (confirmed or pending). Their other factors and
     * recovery codes stay. Audited as `user.mfa_sms_removed`, with the actor — an
     * administrator removing it is recorded as such, not as the person.
     */
    public function remove(string $userId, ?ActorType $actorType = null, ?string $actorId = null): bool;
}
