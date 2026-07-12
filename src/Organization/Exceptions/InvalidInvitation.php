<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

/**
 * Thrown when an invitation token is unknown, already used, revoked, or expired.
 */
final class InvalidInvitation extends RuntimeException
{
    public static function make(): self
    {
        return new self('This invitation is invalid, already used, or has expired.');
    }
}
