<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\Support;

use Carbon\CarbonImmutable;
use Throwable;

/**
 * Reading loosely-typed HR API payloads without trusting their shape.
 *
 * Every HR API returns JSON somebody else designed: a number where a string was documented,
 * an empty string meaning null, `0000-00-00` meaning "no termination date" (BambooHR), a
 * value wrapped in `{label, value}` (Personio). These helpers turn whatever arrived into
 * the one type the mapper wants, or null — never an exception, because one malformed
 * record must cost one record, not the run.
 */
final class HrisValues
{
    /**
     * A value at a path of keys, literal keys only (a key may itself contain a dot).
     *
     * @param  array<mixed>  $data
     */
    public static function at(array $data, string ...$path): mixed
    {
        $value = $data;

        foreach ($path as $key) {
            if (! is_array($value) || ! array_key_exists($key, $value)) {
                return null;
            }

            $value = $value[$key];
        }

        return $value;
    }

    /**
     * A non-empty trimmed string at a path, or null. Numbers are read as their string form
     * (employee ids are often integers on the wire).
     *
     * @param  array<mixed>  $data
     */
    public static function string(array $data, string ...$path): ?string
    {
        return self::stringOf(self::at($data, ...$path));
    }

    public static function stringOf(mixed $value): ?string
    {
        if (is_int($value) || is_float($value)) {
            $value = (string) $value;
        }

        if (! is_string($value)) {
            return null;
        }

        $value = trim($value);

        return $value === '' ? null : $value;
    }

    /**
     * A calendar date at a path, or null for anything that is not one — including the
     * all-zero dates some HR systems use for "never".
     *
     * @param  array<mixed>  $data
     */
    public static function date(array $data, string ...$path): ?CarbonImmutable
    {
        return self::dateOf(self::at($data, ...$path));
    }

    public static function dateOf(mixed $value): ?CarbonImmutable
    {
        $value = self::stringOf($value);

        if ($value === null || str_starts_with($value, '0000-00-00')) {
            return null;
        }

        try {
            return CarbonImmutable::parse($value)->startOfDay();
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * A truthy flag: `true`, `1`, `"1"`, `"true"`, `"yes"` (Workday reports a boolean as
     * `"1"`/`"0"`). Null when absent or unreadable.
     *
     * @param  array<mixed>  $data
     */
    public static function bool(array $data, string ...$path): ?bool
    {
        $value = self::at($data, ...$path);

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value !== 0;
        }

        $value = self::stringOf($value);

        if ($value === null) {
            return null;
        }

        return match (strtolower($value)) {
            '1', 'true', 'yes', 'y' => true,
            '0', 'false', 'no', 'n' => false,
            default => null,
        };
    }

    /**
     * A scalar suitable for passing through as a custom attribute: strings, numbers and
     * booleans as they are, anything structured flattened to its `value`/`name`/`label`
     * when it has one, otherwise dropped.
     */
    public static function scalar(mixed $value): string|int|float|bool|null
    {
        if (is_string($value) || is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return is_string($value) ? (trim($value) === '' ? null : trim($value)) : $value;
        }

        if (is_array($value)) {
            foreach (['value', 'name', 'label', 'displayName', 'id'] as $key) {
                if (array_key_exists($key, $value) && ! is_array($value[$key])) {
                    return self::scalar($value[$key]);
                }
            }
        }

        return null;
    }

    /**
     * Pick the requested custom attributes off a record, by the provider's own field name.
     *
     * @param  array<mixed>  $record
     * @param  list<string>  $names
     * @param  (\Closure(array<mixed>, string): mixed)|null  $read  how to find a named field; a literal key by default
     * @return array<string, scalar|null>
     */
    public static function custom(array $record, array $names, ?\Closure $read = null): array
    {
        $out = [];

        foreach ($names as $name) {
            $value = $read !== null ? $read($record, $name) : self::at($record, $name);
            $out[$name] = self::scalar($value);
        }

        return $out;
    }
}
