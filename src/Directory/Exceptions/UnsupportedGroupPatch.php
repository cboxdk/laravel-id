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
}
