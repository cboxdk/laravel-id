<?php

declare(strict_types=1);

namespace Cbox\Id\Otp\Contracts;

use Cbox\Id\Otp\KeyedOtpHasher;

/**
 * Turns a plaintext one-time passcode into the value stored at rest, and verifies
 * a candidate against a stored value in CONSTANT TIME.
 *
 * A short numeric OTP has little entropy (a 6-digit code is a ~2^20 space), so a
 * plain fast hash in the database would be trivially brute-forced offline after a
 * dump. The shipped {@see KeyedOtpHasher} therefore uses a KEYED hash
 * (HMAC under a key derived from the crypto master key, which lives outside the
 * database) — a dump alone does not reveal the code.
 */
interface OtpHasher
{
    public function hash(string $code): string;

    /**
     * Constant-time compare. Callers MUST run this even on a miss (no stored
     * challenge) using {@see decoy()} so timing never distinguishes a wrong code
     * from an unknown recipient.
     */
    public function verify(string $code, string $storedHash): bool;

    /**
     * A well-formed but never-matching stored hash, so the miss path performs the
     * same compare work as the hit path.
     */
    public function decoy(): string;
}
