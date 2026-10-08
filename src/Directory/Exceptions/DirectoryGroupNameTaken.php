<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use RuntimeException;

/**
 * A group `displayName` already used by another group of the same directory.
 *
 * The store has always kept display names unique per directory (a unique index), and
 * Microsoft Entra ID matches groups on it; a duplicate create used to surface as the
 * database's constraint violation — a 500 — where RFC 7644 §3.3 requires
 * `409 uniqueness`.
 */
class DirectoryGroupNameTaken extends RuntimeException
{
    public static function make(string $displayName): self
    {
        return new self("A group named [{$displayName}] already exists in this directory.");
    }
}
