<?php

declare(strict_types=1);

namespace Cbox\Id\Otp;

use Cbox\Id\Otp\Contracts\OtpHasher;

/**
 * Keyed HMAC-SHA256 hasher for one-time passcodes.
 *
 * WHY KEYED, NOT bcrypt/argon2 OR a plain hash:
 *
 *  - A short numeric OTP has little entropy (a 6-digit code is a ~2^20 space). A
 *    plain fast hash (SHA-256) of it could be brute-forced offline in ~a million
 *    tries the instant the table is dumped. So the at-rest value MUST be either
 *    slow (bcrypt/argon2) OR keyed (HMAC under a secret the database does not
 *    hold).
 *  - We choose KEYED. The verify path is hit on every guess an attacker makes; a
 *    slow password hash there turns the attempt-cap + rate-limiter into a CPU
 *    amplification lever (each guess costs a full bcrypt). HMAC is cheap and
 *    constant-time, so the caps — not hash slowness — do the security work, which
 *    is exactly where we want the guarantee to rest.
 *  - The HMAC key is derived from the crypto MASTER KEY via HKDF, and the master
 *    key lives outside the database (config / secret store, same key that seals
 *    MFA secrets). A database dump therefore does not reveal the codes: an
 *    attacker also needs the master key. Compromise both and the online caps +
 *    5-minute TTL are still in force.
 *
 * All primitives are vetted PHP core: {@see hash_hkdf}, {@see hash_hmac},
 * {@see hash_equals}. Nothing here is hand-rolled.
 */
class KeyedOtpHasher implements OtpHasher
{
    /**
     * A 32-byte HMAC subkey, domain-separated from the master key so this use can
     * never collide with any other consumer of the same master key.
     */
    private readonly string $subKey;

    public function __construct(string $masterKey)
    {
        $this->subKey = hash_hkdf('sha256', $masterKey, 0, 'cbox-id:otp:code:v1');
    }

    public function hash(string $code): string
    {
        return hash_hmac('sha256', $code, $this->subKey);
    }

    public function verify(string $code, string $storedHash): bool
    {
        return hash_equals($storedHash, $this->hash($code));
    }

    public function decoy(): string
    {
        // A real, well-formed hash of a value no valid code can equal, so the miss
        // path runs the identical hash_equals work as a hit.
        return $this->hash("\0decoy\0");
    }
}
