<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Exceptions;

use RuntimeException;

/**
 * Thrown when a SCIM Group PATCH carries an operation the directory cannot honour —
 * an unknown `op` or a `path` outside the supported set. The SCIM layer maps this to
 * a `400` with the appropriate `scimType` rather than returning `200` with no change,
 * which would let an IdP believe a membership edit applied when it silently did not.
 */
class UnsupportedGroupPatch extends RuntimeException
{
    /**
     * @param  string  $scimType  the SCIM error keyword (RFC 7644 §3.12), e.g.
     *                            `invalidSyntax` for an unknown op or `invalidPath`
     *                            for an unsupported path
     */
    public function __construct(string $message, public readonly string $scimType)
    {
        parent::__construct($message);
    }

    public static function op(string $op): self
    {
        return new self(
            $op === '' ? 'Missing PATCH op.' : "Unsupported PATCH op: {$op}.",
            'invalidSyntax',
        );
    }

    public static function path(string $path): self
    {
        return new self("Unsupported PATCH path: {$path}.", 'invalidPath');
    }

    /**
     * RFC 7644 §3.5.2.2: "If 'path' is unspecified, the operation fails with HTTP status
     * code 400 and a 'scimType' error code of 'noTarget'."
     *
     * The User side has always answered this way. The Group side admitted the empty path
     * and let a pathless `remove` reach `detach()` — so a connector that dropped `path`
     * on a membership operation emptied the group and got a 200 back, which it recorded
     * as success and never retried. Membership changes drive the group→role bridge, so
     * that was a silent mass revocation.
     */
    public static function noTarget(): self
    {
        return new self('A PATCH operation must name a target path.', 'noTarget');
    }

    /**
     * A pathless `add`/`replace` whose `value` is not an object. With no `path` the
     * target is the resource itself, and `value` must be the attributes to set
     * (RFC 7644 §3.5.2.1, §3.5.2.3) — a scalar there names nothing to write.
     */
    public static function notAnObject(): self
    {
        return new self('A PATCH operation without a path must carry an object of attributes as its value.', 'invalidValue');
    }
}
