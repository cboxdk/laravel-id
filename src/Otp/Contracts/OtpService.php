<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Contracts;

use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Cbox\Id\Otp\Exceptions\OtpRateLimitExceeded;
use Cbox\Id\Otp\Exceptions\UnknownOtpChannel;
use Cbox\Id\Otp\ValueObjects\OtpChallenge;
use Cbox\Id\Otp\ValueObjects\OtpResult;

/**
 * Issues and verifies short-lived, single-use one-time passcodes delivered over a
 * channel (email, SMS, …) as a verification / MFA factor.
 *
 * The code itself is generated with a CSPRNG, delivered ONCE via the channel, and
 * only ever stored as a keyed hash (see {@see OtpHasher}). The caller receives an
 * {@see OtpChallenge} describing the issued challenge — never the plaintext code.
 * Verification is constant-time, single-use, TTL-bounded, attempt-capped and
 * rate-limited (see {@see DatabaseOtpService}).
 */
interface OtpService
{
    /**
     * Generate a fresh code for `purpose`, store only its hash, and deliver it to
     * `recipient` over the named `channel`. `ip` (the request IP, when known) is
     * folded into the per-recipient issue rate limit so the endpoint cannot be used
     * to bomb a recipient or run up an SMS bill.
     *
     * @throws UnknownOtpChannel when no sender is registered for `channel`
     * @throws OtpRateLimitExceeded when issuing exceeds the per-recipient window
     * @throws EnvironmentMissing when no environment is in context
     */
    public function issue(string $purpose, string $recipient, string $channel, ?string $ip = null): OtpChallenge;

    /**
     * Verify a code against a challenge selected by its id. The result is uniform:
     * an unknown, expired, consumed, locked or wrong code all fail, and the
     * hash-compare runs on every path so a miss is indistinguishable from a wrong
     * code by timing. `ip` drives the global anti-brute-force verify throttle.
     */
    public function verify(string $challengeId, string $code, ?string $ip = null): OtpResult;

    /**
     * Verify a code against the most recent live challenge for `recipient` +
     * `purpose`. A recipient with no live challenge fails exactly as a wrong code
     * does (no enumeration). `ip` drives the global verify throttle.
     */
    public function verifyLatest(string $purpose, string $recipient, string $code, ?string $ip = null): OtpResult;
}
