<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use InvalidArgumentException;

/**
 * A submitted app manifest was malformed — a bad shape, a missing key, or a role
 * referencing a permission it never declared. Rejected whole; a partial catalog is
 * never persisted.
 */
class InvalidManifest extends InvalidArgumentException
{
    public static function make(string $reason): self
    {
        return new self("Invalid app manifest: {$reason}");
    }
}
