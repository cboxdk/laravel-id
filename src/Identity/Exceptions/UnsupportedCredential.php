<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * Thrown when a credential uses a key type, algorithm or attestation format the
 * verifier does not support — never silently trusted.
 */
class UnsupportedCredential extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('unsupported credential: '.$reason);
    }
}
