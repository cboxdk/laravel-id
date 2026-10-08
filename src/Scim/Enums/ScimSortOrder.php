<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Enums;

/**
 * The `sortOrder` query parameter (RFC 7644 §3.4.2.3): "Allowed values are
 * 'ascending' and 'descending'", ascending being the default whenever `sortBy` is
 * given without one.
 */
enum ScimSortOrder: string
{
    case Ascending = 'ascending';
    case Descending = 'descending';

    /**
     * Parsed without regard to case — the RFC names the two values but says nothing
     * about their spelling, and a client sending `Descending` means exactly that. Null
     * for anything else, which the caller refuses with `invalidValue` rather than
     * quietly sorting the other way.
     */
    public static function tryParse(mixed $value): ?self
    {
        return is_string($value) ? self::tryFrom(strtolower(trim($value))) : null;
    }
}
