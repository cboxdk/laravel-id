<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

use Carbon\CarbonImmutable;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Scim\ScimSchema;
use Cbox\Id\Scim\Support\ScimBoolean;
use Illuminate\Support\Str;
use Throwable;

/**
 * What KIND of value a filterable directory attribute holds — which decides both the
 * operators that are meaningful on it and how a filter's literal must be coerced
 * before it reaches the query.
 *
 * Typing this is what stops a filter from quietly matching the wrong rows: a literal
 * that cannot be a value of the attribute at all (`active eq "fasle"`,
 * `meta.lastModified gt "yesterday"`) is refused as `invalidFilter` instead of being
 * coerced into `false` / epoch and answering with a confidently wrong result set.
 */
enum ScimValueType
{
    /** xsd:dateTime as RFC 7643 §2.3.5 defines it on the wire, and nothing else. */
    private const DATE_TIME = '/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/i';

    /** Compared byte-for-byte (client-assigned opaque identifiers). */
    case CaseSensitiveText;

    /**
     * RFC 7643 `caseExact: false`. Stored pre-folded in its own column, so the
     * comparison literal is folded to match — see
     * {@see DirectoryUser::normalize()}.
     */
    case CaseInsensitiveText;

    case Boolean;

    case Timestamp;

    /**
     * Whether this type answers the given SCIM operator meaningfully.
     *
     * Ordering comparisons are allowed only where the server actually implements an
     * ordering — the `meta.lastModified` watermark delta-sync depends on. Substring
     * operators are allowed only on text. Everything else stays refused rather than
     * being answered with a LIKE against a boolean column.
     */
    public function supports(string $operator): bool
    {
        return match ($operator) {
            'gt', 'ge', 'lt', 'le' => $this === self::Timestamp,
            'co', 'sw', 'ew' => $this === self::CaseSensitiveText || $this === self::CaseInsensitiveText,
            default => true,
        };
    }

    /**
     * Coerce a filter literal onto the value the column stores, or null when the
     * literal is not a value of this type at all.
     */
    public function coerce(string $value): string|bool|null
    {
        return match ($this) {
            self::CaseSensitiveText => $value,
            self::CaseInsensitiveText => Str::lower(trim($value)),
            self::Boolean => ScimBoolean::parse($value),
            self::Timestamp => self::timestamp($value),
        };
    }

    /**
     * An RFC 7643 §2.3.5 datetime literal (xsd:dateTime), rebased onto the timeline the
     * timestamp COLUMN is stored in — so the comparison is against one timeline and one
     * shape.
     *
     * That timeline is `config('app.timezone')`, not UTC: Eloquent writes `created_at` /
     * `updated_at` in the application timezone, while {@see ScimSchema::dateTime()}
     * EMITS `meta.lastModified` converted to UTC. Coercing the client's literal with
     * `->utc()` compared the two in different frames, and the two frames only agree at
     * offset 0 — which is precisely what testbench pins, so the suite could not see it.
     * With `app.timezone = America/New_York` a row modified at 10:00 local is stored
     * `10:00:00` and handed out as `14:00:00Z`; the watermark the IdP stores then comes
     * back as `meta.lastModified gt "…14:00:00Z"`, compares `14:00:00 > 10:00:00`, and
     * every incremental sync returns zero rows — forever, at 200 OK. East of UTC the
     * same mismatch inverts into a permanent full re-sync.
     *
     * Shape-checked BEFORE parsing: Carbon happily accepts English relative expressions
     * ("yesterday", "now") and bare integers, so a mis-serialized or hostile watermark
     * would parse into a real instant and silently return the wrong slice of the
     * directory. Only the wire format SCIM actually defines is accepted.
     */
    private static function timestamp(string $value): ?string
    {
        if (preg_match(self::DATE_TIME, trim($value)) !== 1) {
            return null;
        }

        $timezone = config('app.timezone');

        try {
            return CarbonImmutable::parse(trim($value))
                ->setTimezone(is_string($timezone) && $timezone !== '' ? $timezone : 'UTC')
                ->format('Y-m-d H:i:s');
        } catch (Throwable) {
            return null;
        }
    }
}
