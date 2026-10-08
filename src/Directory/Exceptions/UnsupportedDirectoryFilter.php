<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use RuntimeException;

/**
 * Thrown when a SCIM list filter falls outside the subset the directory supports.
 * The SCIM layer maps this to a `400 invalidFilter` rather than silently
 * returning a mismatched (or unfiltered) result set.
 */
class UnsupportedDirectoryFilter extends RuntimeException
{
    public static function make(string $filter): self
    {
        return new self('Unsupported directory filter: '.$filter);
    }

    /**
     * A filter refused for a specific, reportable reason — a parse error at an offset,
     * an attribute the store does not hold, an operator the attribute's type cannot
     * answer. The message is written for the human reading the SCIM error `detail`.
     */
    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
