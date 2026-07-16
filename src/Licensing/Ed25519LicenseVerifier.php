<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing;

use Cbox\Id\Licensing\Contracts\LicenseVerifier;
use Cbox\Id\Licensing\Exceptions\LicenseException;
use Cbox\Id\Licensing\Support\Base64Url;
use Cbox\Id\Licensing\Support\LicenseFormat;
use Cbox\Id\Licensing\ValueObjects\License;
use Illuminate\Support\Carbon;

/**
 * Verifies a license token with libsodium's Ed25519 — a vetted primitive, no
 * bespoke crypto. The algorithm is fixed (there is no `alg` field to confuse), the
 * public key is supplied by config, and time bounds are checked with a small clock
 * skew. Verification is fully offline.
 */
final class Ed25519LicenseVerifier implements LicenseVerifier
{
    /**
     * @param  string  $publicKey  the raw 32-byte Ed25519 public key
     * @param  int  $clockSkewSeconds  tolerance for nbf/exp against wall-clock drift
     */
    public function __construct(
        private readonly string $publicKey,
        private readonly int $clockSkewSeconds = 60,
    ) {
        if (strlen($this->publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw LicenseException::malformed('public key must be '.SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES.' bytes');
        }
    }

    public function verify(string $token): License
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3 || $parts[0] !== LicenseFormat::PREFIX) {
            throw LicenseException::malformed('expected three CBXLIC1 segments');
        }

        $signature = Base64Url::decode($parts[2]);

        if ($signature === null || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw LicenseException::malformed('invalid signature segment');
        }

        $signingInput = LicenseFormat::signingInput($parts[1]);

        if (! sodium_crypto_sign_verify_detached($signature, $signingInput, $this->publicKey)) {
            throw LicenseException::badSignature();
        }

        $payload = Base64Url::decode($parts[1]);

        if ($payload === null) {
            throw LicenseException::malformed('undecodable payload');
        }

        $claims = json_decode($payload, true);

        if (! is_array($claims)) {
            throw LicenseException::malformed('payload is not a JSON object');
        }

        /** @var array<string, mixed> $claims */
        $license = License::fromClaims($claims);

        $now = Carbon::now()->getTimestamp();

        if ($license->notBefore > $now + $this->clockSkewSeconds) {
            throw LicenseException::notYetValid();
        }

        if ($license->expiresAt < $now - $this->clockSkewSeconds) {
            throw LicenseException::expired();
        }

        return $license;
    }
}
