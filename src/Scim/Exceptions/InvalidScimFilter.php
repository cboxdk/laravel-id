<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Exceptions;

use InvalidArgumentException;

/**
 * A SCIM filter or PATCH path that does not parse (RFC 7644 §3.4.2.2 Figure 1,
 * §3.5.2), or that exceeds the parser's size and nesting limits.
 *
 * Transport-agnostic on purpose: the SCIM server turns it into `400 invalidFilter`
 * (for a `filter` parameter) or `400 invalidPath` (for a PATCH `path`); the message is
 * written for the human reading that error body, and names the offset where the
 * parser gave up.
 */
class InvalidScimFilter extends InvalidArgumentException
{
    public static function at(string $reason, int $position): self
    {
        return new self(sprintf('%s at position %d.', $reason, $position + 1));
    }

    public static function tooLong(int $limit): self
    {
        return new self("The filter is longer than the {$limit} characters this server accepts.");
    }

    public static function tooDeep(int $limit): self
    {
        return new self("The filter nests deeper than the {$limit} levels this server accepts.");
    }

    public static function tooManyTerms(int $limit): self
    {
        return new self("The filter has more than the {$limit} comparisons this server accepts.");
    }

    public static function empty(): self
    {
        return new self('The filter is empty.');
    }
}
