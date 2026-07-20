<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * Thrown when an IdP response fails validation — bad signature, wrong issuer or
 * audience, expired, or malformed. Never carries the raw assertion.
 */
class InvalidAssertion extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('invalid assertion: '.$reason);
    }
}
