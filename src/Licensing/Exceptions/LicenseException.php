<?php

declare(strict_types=1);

namespace Cbox\Id\Licensing\Exceptions;

use RuntimeException;

/**
 * A license token could not be trusted — malformed, wrong signature, expired, or
 * not yet valid. Callers treat any of these as "unlicensed" (deny-by-default): a
 * license that cannot be verified grants nothing.
 */
final class LicenseException extends RuntimeException
{
    public static function malformed(string $why): self
    {
        return new self('Malformed license token: '.$why);
    }

    public static function badSignature(): self
    {
        return new self('License signature verification failed.');
    }

    public static function notYetValid(): self
    {
        return new self('License is not valid yet (nbf in the future).');
    }

    public static function expired(): self
    {
        return new self('License has expired.');
    }

    public static function noPublicKey(): self
    {
        return new self('No license public key is configured; cannot verify licenses.');
    }
}
