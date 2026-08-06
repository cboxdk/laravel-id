<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * Thrown when explicitly linking a provider identity that is already linked to a
 * DIFFERENT account. A given external identity can belong to exactly one subject.
 */
class IdentityAlreadyLinked extends RuntimeException
{
    public static function make(string $provider): self
    {
        return new self("This {$provider} identity is already linked to another account.");
    }
}
