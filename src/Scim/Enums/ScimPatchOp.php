<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Enums;

/**
 * The complete, closed set of SCIM 2.0 PATCH operations (RFC 7644 §3.5.2):
 * `add`, `remove`, `replace` — and nothing else.
 *
 * Deny-by-default belongs in ONE place. Both PATCH surfaces (the User mapper and the
 * Group directory) previously carried their own literal copy of this list, which is
 * exactly how the two drifted apart: the Group side refused an unknown `op` while the
 * User side fell through to a `replace` default. Anything this enum cannot parse is a
 * client error the caller must turn into a 400 `invalidSyntax` — never a 200 the
 * calling IdP records as a successful write and never retries.
 */
enum ScimPatchOp: string
{
    case Add = 'add';
    case Remove = 'remove';
    case Replace = 'replace';

    /**
     * Parse an operation's wire `op` member. Null when the member is absent, is not
     * a string, or names an operation RFC 7644 §3.5.2 does not define.
     */
    public static function tryParse(mixed $value): ?self
    {
        return is_string($value) ? self::tryFrom(strtolower(trim($value))) : null;
    }

    /**
     * The `op` exactly as it arrived, for the error message. An absent or non-string
     * member renders as the empty string so the caller can distinguish "missing op"
     * from "unsupported op" without re-inspecting the payload.
     */
    public static function label(mixed $value): string
    {
        return is_string($value) ? trim($value) : '';
    }
}
