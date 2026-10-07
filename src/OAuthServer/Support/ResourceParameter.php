<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Illuminate\Http\Request;

/**
 * Reads the RFC 8707 `resource` parameter off a request — the token endpoint's, the PAR
 * endpoint's, and the host's `/authorize` — the same way everywhere.
 *
 * ONE RESOURCE PER REQUEST, AND COUNTED ON THE WIRE. RFC 8707 lets a client repeat the
 * parameter (`resource=a&resource=b`), and PHP's own parser keeps only the LAST of a
 * repeated key: `$request->input('resource')` would quietly answer `b` and a token for one
 * audience would be minted for a request that named two. So the raw query string and form
 * body are read and the occurrences counted before anything else, and two or more are
 * refused with `invalid_target` ({@see InvalidAudience::multipleResources()} says why this
 * server issues single-audience tokens only).
 *
 * A present-but-malformed value is refused too, never dropped: a token issued unbound
 * would be audienced to the issuer, which is wider than what the client asked for.
 */
final class ResourceParameter
{
    /**
     * The one `resource` the request names, or null when it names none.
     *
     * @throws InvalidAudience `invalid_target` for several values or a malformed one
     */
    public static function fromRequest(Request $request): ?string
    {
        $query = $request->server->get('QUERY_STRING');
        $occurrences = self::occurrences(is_string($query) ? $query : '');

        if (self::isFormBody($request)) {
            $occurrences += self::occurrences($request->getContent());
        }

        if ($occurrences > 1) {
            throw InvalidAudience::multipleResources();
        }

        return self::fromValue($request->input('resource'));
    }

    /**
     * The same rule for a value already lifted off the wire — a pushed authorization
     * request's stored parameters, a JSON body.
     *
     * @throws InvalidAudience
     */
    public static function fromValue(mixed $value): ?string
    {
        if (is_array($value)) {
            $values = array_values(array_filter($value, static fn (mixed $item): bool => ! (is_string($item) && trim($item) === '')));

            if (count($values) > 1) {
                throw InvalidAudience::multipleResources();
            }

            $value = $values[0] ?? null;
        }

        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw InvalidAudience::malformedResource();
        }

        $value = trim($value);

        if ($value === '') {
            return null;
        }

        if (! ResourceIndicator::isWellFormed($value)) {
            throw InvalidAudience::malformedResource();
        }

        return $value;
    }

    /**
     * How many times a `resource` (or `resource[...]`) key appears in a
     * `application/x-www-form-urlencoded` string.
     */
    private static function occurrences(string $encoded): int
    {
        if ($encoded === '') {
            return 0;
        }

        $count = 0;

        foreach (explode('&', $encoded) as $pair) {
            $key = urldecode(explode('=', $pair, 2)[0]);

            if ($key === 'resource' || str_starts_with($key, 'resource[')) {
                $count++;
            }
        }

        return $count;
    }

    private static function isFormBody(Request $request): bool
    {
        $type = strtolower((string) $request->headers->get('Content-Type', ''));

        return str_starts_with($type, 'application/x-www-form-urlencoded');
    }
}
