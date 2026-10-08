<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

use Cbox\Id\Scim\Enums\ScimComparisonOperator;
use Cbox\Id\Scim\Support\ScimBoolean;
use Illuminate\Support\Str;

/**
 * The RFC 7643 §2.3 type of a queryable directory attribute, as the filter translator
 * and the sorter need it: which operators it answers, and what a literal must look like
 * to be a value of it.
 *
 * The successor of {@see ScimValueType} for the full filter grammar. That enum stays as
 * it was — its `supports()` refuses ordering on text, which is what the older
 * single-clause parser built on it promises — while this one follows RFC 7644
 * §3.4.2.2 to the letter: ordering is lexicographical on strings and chronological on
 * DateTime, and on a Boolean it "SHALL cause a failed response".
 */
enum ScimAttributeType
{
    /** `caseExact: true` — client-assigned and opaque identifiers. */
    case CaseExactString;

    /** `caseExact: false` — compared, and sorted, without regard to case. */
    case CaseInsensitiveString;

    case Boolean;

    case DateTime;

    public function supports(ScimComparisonOperator $operator): bool
    {
        return match (true) {
            $operator->isSubstring() => $this->isString(),
            $operator->isOrdering() => $this !== self::Boolean,
            default => true,
        };
    }

    public function isString(): bool
    {
        return $this === self::CaseExactString || $this === self::CaseInsensitiveString;
    }

    /**
     * The literal coerced onto what the column stores, or null when it cannot be a
     * value of this type at all — in which case the WHOLE filter is refused rather than
     * coerced into something that answers with the wrong rows (`active eq "fasle"` is
     * not `active eq false`).
     *
     * A number is accepted for a string attribute (`employeeNumber eq 1042` is plainly
     * meant as text); a DateTime must be an RFC 7643 §2.3.5 xsd:dateTime string, rebased
     * onto the frame the timestamp columns are stored in (see {@see ScimValueType}).
     */
    public function coerce(string|int|float|bool $value): string|bool|null
    {
        return match ($this) {
            self::CaseExactString => is_bool($value) ? null : (string) $value,
            self::CaseInsensitiveString => is_bool($value) ? null : Str::lower((string) $value),
            self::Boolean => ScimBoolean::parse($value),
            self::DateTime => is_string($value) ? self::dateTime($value) : null,
        };
    }

    private static function dateTime(string $value): ?string
    {
        $coerced = ScimValueType::Timestamp->coerce($value);

        return is_string($coerced) ? $coerced : null;
    }
}
