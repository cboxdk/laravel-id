<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Support;

/**
 * The on-prem license token format, shared by the signer (issuer) and the verifier
 * so they can never drift.
 *
 * A token is three dot-separated segments:
 *
 *     CBXLIC1.<base64url(claims-json)>.<base64url(ed25519-signature)>
 *
 * The signature is an Ed25519 detached signature over the ASCII bytes of the first
 * two segments (`CBXLIC1.<payload>`), so the exact transmitted bytes are what's
 * signed — no canonicalization ambiguity.
 */
final class LicenseFormat
{
    public const PREFIX = 'CBXLIC1';

    public static function signingInput(string $encodedPayload): string
    {
        return self::PREFIX.'.'.$encodedPayload;
    }
}
