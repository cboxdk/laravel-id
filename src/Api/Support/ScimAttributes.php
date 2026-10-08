<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Support;

use Illuminate\Http\Request;

/**
 * Case-insensitive reads of a SCIM request body.
 *
 * RFC 7643 §2.1 is explicit: "Attribute names are case-insensitive". This package honoured
 * that on PATCH — {@see ScimMapper} lowercases the path before matching — and nowhere
 * else. POST and PUT read `userName`, `displayName`, `members` and the `name.*` parts with
 * exact casing off the request, so a conformant provisioner sending `UserName` or
 * `displayname` had its value silently read as empty: a create landing with no username,
 * or a group replace dropping its whole member list. PATCH worked and POST did not, from
 * the same client, against the same server.
 *
 * The lookup is built once per read from the top-level keys, which is small — a SCIM
 * resource body has a handful of attributes — and nested paths are walked segment by
 * segment so `name.givenName` matches `Name.GivenName` too.
 *
 * Values are returned untouched. Only the NAMES are case-insensitive; a `userName` of
 * "Ada" is not the same as "ada" and this must never pretend otherwise.
 */
final class ScimAttributes
{
    public static function string(Request $request, string $path): string
    {
        return self::stringValue($request->all(), $path);
    }

    /**
     * @param  array<array-key, mixed>  $data
     */
    public static function stringValue(array $data, string $path): string
    {
        $value = self::value($data, $path);

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * The raw value at a dot path, matched without regard to case, or null.
     */
    public static function get(Request $request, string $path): mixed
    {
        return self::value($request->all(), $path);
    }

    /**
     * The same read over a decoded body — a `/Bulk` operation's `data` has no Request
     * of its own, and must be read by exactly the rules a single-resource request is.
     *
     * @param  array<array-key, mixed>  $data
     */
    public static function value(array $data, string $path): mixed
    {
        $cursor = $data;
        $value = null;

        $segments = explode('.', $path);

        foreach ($segments as $index => $segment) {
            $key = self::matchKey($cursor, $segment);

            if ($key === null) {
                return null;
            }

            $value = $cursor[$key];

            if (is_array($value)) {
                $cursor = $value;
            } elseif ($index < count($segments) - 1) {
                // `name.givenName` against a `name` that is a plain string: there is no
                // sub-attribute to find. Carrying on would look `givenName` up one level
                // too high.
                return null;
            }
        }

        return $value;
    }

    /**
     * The actual key in this array whose name matches, ignoring case.
     *
     * An exact hit wins without scanning — the overwhelmingly common case, since most
     * clients do send the canonical spelling.
     *
     * @param  array<array-key, mixed>  $values
     */
    private static function matchKey(array $values, string $name): ?string
    {
        if (array_key_exists($name, $values)) {
            return $name;
        }

        $needle = strtolower($name);

        foreach (array_keys($values) as $key) {
            if (strtolower((string) $key) === $needle) {
                return (string) $key;
            }
        }

        return null;
    }
}
