<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto;

/**
 * RFC 6238 (TOTP) over RFC 4238 (HOTP), built on the vetted `hash_hmac`
 * primitive. Verified against the RFC 6238 test vectors — see the test suite.
 *
 * SHA-1, 30-second period, 6 digits — the interoperable defaults every
 * authenticator app supports.
 */
class TotpAuthenticator
{
    private const PERIOD = 30;

    private const DIGITS = 6;

    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a fresh base32-encoded 160-bit secret.
     */
    public function generateSecret(): string
    {
        return $this->base32Encode(random_bytes(20));
    }

    /**
     * The current TOTP code for a secret at a given time.
     */
    public function codeAt(string $base32Secret, int $timestamp): string
    {
        return $this->hotp($this->base32Decode($base32Secret), intdiv($timestamp, self::PERIOD));
    }

    /**
     * Verify a code within a ± window of time steps (tolerating small clock skew).
     */
    public function verify(string $base32Secret, string $code, ?int $timestamp = null, int $window = 1): bool
    {
        return $this->matchStep($base32Secret, $code, $timestamp, $window) !== null;
    }

    /**
     * Like verify(), but returns the time step (counter) the code matched, or null
     * if it matched none. The caller persists the last accepted step so a code —
     * or any code within the same skew window — can't be replayed until time moves
     * past it. Every candidate step is checked (no short-circuit) to keep the
     * comparison time independent of which offset matched.
     */
    public function matchStep(string $base32Secret, string $code, ?int $timestamp = null, int $window = 1): ?int
    {
        $timestamp ??= time();
        $key = $this->base32Decode($base32Secret);
        $counter = intdiv($timestamp, self::PERIOD);

        $matched = null;

        for ($offset = -$window; $offset <= $window; $offset++) {
            $step = $counter + $offset;

            if (hash_equals($this->hotp($key, $step), $code)) {
                $matched = $step;
            }
        }

        return $matched;
    }

    /**
     * The `otpauth://` provisioning URI for QR enrolment.
     */
    public function provisioningUri(string $base32Secret, string $account, string $issuer): string
    {
        $label = rawurlencode($issuer.':'.$account);

        return 'otpauth://totp/'.$label.'?'.http_build_query([
            'secret' => $base32Secret,
            'issuer' => $issuer,
            'algorithm' => 'SHA1',
            'digits' => self::DIGITS,
            'period' => self::PERIOD,
        ]);
    }

    private function hotp(string $key, int $counter): string
    {
        $binary = pack('N', 0).pack('N', $counter); // 8-byte big-endian counter
        $hash = hash_hmac('sha1', $binary, $key, true);

        $lastByte = ord($hash[strlen($hash) - 1]);
        $start = $lastByte & 0x0F;

        $value = ((ord($hash[$start]) & 0x7F) << 24)
            | ((ord($hash[$start + 1]) & 0xFF) << 16)
            | ((ord($hash[$start + 2]) & 0xFF) << 8)
            | (ord($hash[$start + 3]) & 0xFF);

        return str_pad((string) ($value % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    private function base32Encode(string $data): string
    {
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            $output .= self::ALPHABET[(int) bindec(str_pad($chunk, 5, '0', STR_PAD_RIGHT))];
        }

        return $output;
    }

    private function base32Decode(string $secret): string
    {
        $bits = '';
        foreach (str_split(strtoupper($secret)) as $char) {
            $index = strpos(self::ALPHABET, $char);
            if ($index === false) {
                continue;
            }
            $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $output .= chr(((int) bindec($byte)) & 0xFF);
            }
        }

        return $output;
    }
}
