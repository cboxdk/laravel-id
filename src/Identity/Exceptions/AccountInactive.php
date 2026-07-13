<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

/**
 * Thrown when authentication is attempted for a subject that is not active
 * (disabled by an admin, deprovisioned by the directory, or locked). A
 * deactivated account must never be able to establish a new session — revoking
 * existing sessions is not enough if the login paths don't also refuse.
 */
final class AccountInactive extends RuntimeException
{
    public static function make(string $subjectId): self
    {
        return new self("The account [{$subjectId}] is not active and cannot authenticate.");
    }
}
