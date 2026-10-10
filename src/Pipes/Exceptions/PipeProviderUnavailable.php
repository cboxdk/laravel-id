<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * The provider could not be reached, answered a 5xx / 429, or answered something that
 * was not a token response. Transient: nothing about the person's authorization is known
 * to have changed.
 */
class PipeProviderUnavailable extends RuntimeException
{
    public static function because(string $reason): self
    {
        return new self("The provider was unavailable ({$reason}).");
    }
}
