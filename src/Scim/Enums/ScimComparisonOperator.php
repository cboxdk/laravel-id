<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Enums;

use Cbox\Id\Scim\Filter\Nodes\PresentNode;

/**
 * The attribute operators of a SCIM filter that compare against a value
 * (RFC 7644 §3.4.2.2, Table 3). `pr` is not here: it takes no value, so it is its own
 * node ({@see PresentNode}) rather than an operator that
 * sometimes has an operand.
 *
 * "Attribute names and attribute operators used in filters are case insensitive", so
 * {@see tryParse()} folds — `userName Eq "john"` is the RFC's own example.
 */
enum ScimComparisonOperator: string
{
    case Equal = 'eq';
    case NotEqual = 'ne';
    case Contains = 'co';
    case StartsWith = 'sw';
    case EndsWith = 'ew';
    case GreaterThan = 'gt';
    case GreaterThanOrEqual = 'ge';
    case LessThan = 'lt';
    case LessThanOrEqual = 'le';

    public static function tryParse(string $operator): ?self
    {
        return self::tryFrom(strtolower($operator));
    }

    /**
     * `gt`/`ge`/`lt`/`le`: lexicographical on strings, chronological on DateTime,
     * numeric on numbers — and a 400 `invalidFilter` on Boolean and Binary, which the
     * RFC makes mandatory ("SHALL cause a failed response").
     */
    public function isOrdering(): bool
    {
        return in_array($this, [self::GreaterThan, self::GreaterThanOrEqual, self::LessThan, self::LessThanOrEqual], true);
    }

    /**
     * `co`/`sw`/`ew`: defined only over strings.
     */
    public function isSubstring(): bool
    {
        return in_array($this, [self::Contains, self::StartsWith, self::EndsWith], true);
    }
}
