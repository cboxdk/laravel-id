<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use RuntimeException;

/**
 * Thrown when a SCIM list filter falls outside the subset the directory supports.
 * The SCIM layer maps this to a `400 invalidFilter` rather than silently
 * returning a mismatched (or unfiltered) result set.
 */
final class UnsupportedDirectoryFilter extends RuntimeException
{
    public static function make(string $filter): self
    {
        return new self('Unsupported directory filter: '.$filter);
    }
}
