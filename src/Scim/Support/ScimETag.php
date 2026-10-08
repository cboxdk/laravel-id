<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Support;

/**
 * SCIM resource versions as HTTP entity-tags (RFC 7644 §3.14, RFC 7232).
 *
 * ## What the tag is
 *
 * A WEAK tag (`W/"…"`) — §3.14 names weak ETags "the preferred mechanism" — derived
 * deterministically from the resource id and its revision counter. The counter is a
 * column bumped on every write that changes the stored resource, so two writes in the
 * same second still yield two tags (a tag derived from `updated_at` alone would not:
 * the column has one-second precision). Hashing the pair keeps the tag opaque — a
 * client cannot guess the next version, and does not need to.
 *
 * ## How tags are compared
 *
 * WEAK comparison everywhere (RFC 7232 §2.3.2): `W/"x"` and `"x"` match. RFC 7232 §3.1
 * asks for STRONG comparison on `If-Match`, under which a weak tag never matches
 * anything — but RFC 7644 §3.14 pairs exactly that header with exactly these tags
 * (`If-Match: W/"e180ee84f0671b1"`), and a strict reading would make SCIM's own example
 * a guaranteed 412. The SCIM reading wins on a SCIM endpoint.
 */
class ScimETag
{
    /**
     * The weak entity-tag of revision `$revision` of resource `$id`.
     */
    public static function forRevision(string $id, int $revision): string
    {
        return self::weak(substr(hash('sha256', $id.'|'.$revision), 0, 20));
    }

    public static function weak(string $opaque): string
    {
        return 'W/"'.$opaque.'"';
    }

    /**
     * Whether `$etag` satisfies an `If-Match` / `If-None-Match` field value: `*`, or a
     * comma-separated list of entity-tags, any one of which matches weakly.
     *
     * A field value that contains no well-formed tag at all matches nothing — for
     * `If-Match` that is a 412, which is the safe failure: a client that sent a
     * precondition it got wrong must not have its write applied unconditionally.
     */
    public static function matches(string $etag, string $header): bool
    {
        $header = trim($header);

        if ($header === '*') {
            return true;
        }

        $current = self::opaque($etag);

        if ($current === null) {
            return false;
        }

        preg_match_all('/(?:W\/)?"([^"]*)"/', $header, $matches);

        return in_array($current, $matches[1], true);
    }

    /**
     * Whether an `If-Match` precondition was given and does NOT hold for `$etag` — the
     * 412 case (RFC 7232 §3.1). No header (or an empty one) is no precondition.
     */
    public static function ifMatchFails(string $etag, ?string $ifMatch): bool
    {
        return $ifMatch !== null && trim($ifMatch) !== '' && ! self::matches($etag, $ifMatch);
    }

    /**
     * Whether an `If-None-Match` precondition was given and matches `$etag` — the 304
     * case of a conditional read (RFC 7232 §3.2).
     */
    public static function ifNoneMatchHolds(string $etag, ?string $ifNoneMatch): bool
    {
        return $ifNoneMatch !== null && trim($ifNoneMatch) !== '' && self::matches($etag, $ifNoneMatch);
    }

    /**
     * The quoted part of an entity-tag, without the weakness indicator.
     */
    private static function opaque(string $etag): ?string
    {
        return preg_match('/^(?:W\/)?"([^"]*)"$/', trim($etag), $m) === 1 ? $m[1] : null;
    }
}
