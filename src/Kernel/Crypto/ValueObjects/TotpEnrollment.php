<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\ValueObjects;

/**
 * Returned once when enrolling TOTP: the base32 secret and the `otpauth://` URI
 * to render as a QR code. Show them once; only the sealed secret is stored.
 */
readonly class TotpEnrollment
{
    public function __construct(
        public string $secret,
        public string $provisioningUri,
    ) {}
}
