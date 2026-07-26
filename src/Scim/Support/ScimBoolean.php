<?php

declare(strict_types=1);

namespace Cbox\Id\Scim\Support;

/**
 * Strict parsing of a SCIM boolean (RFC 7643 §2.3.2).
 *
 * `active` is the most dangerous attribute on the wire: a false value deactivates the
 * account, drops org membership and revokes every session. Both of the coercions this
 * codebase used to reach for — Laravel's `Request::boolean()` and PHP's
 * `FILTER_VALIDATE_BOOLEAN` — answer `false` for ANY value they do not recognise, so
 * `"active": "fasle"` silently became a deprovision that the IdP then recorded as a
 * successful write.
 *
 * RFC 7643 defines the SCIM boolean as the JSON literals `true`/`false`. This parser
 * accepts exactly those, plus the strings `"true"`/`"false"` that connectors which
 * serialize every attribute as a string still send — in ANY case, because Microsoft
 * Entra sends `{"op":"Replace","path":"active","value":"False"}`. Microsoft documents
 * that capital as a client defect corrected only behind the opt-in `?aadOptscim062020`
 * flag, which existing provisioning jobs do not carry; refusing it 400s every
 * termination push, so the account stays active with live sessions and Entra
 * eventually quarantines the whole job.
 *
 * Case folding is NOT coercion. `"fasle"`, `"yes"`, `"1"`, `1` and `0` remain
 * unparsable and return null — the caller MUST refuse the request (400 `invalidValue`)
 * rather than guess which way a typo was meant to go.
 */
class ScimBoolean
{
    /**
     * The parsed boolean, or null when the value is not a SCIM boolean at all.
     */
    public static function parse(mixed $value): ?bool
    {
        if (is_bool($value)) {
            return $value;
        }

        // Case-folded and trimmed, and NOTHING else: no numeric coercion, no
        // truthiness, no prefix matching. Widening past the two spellings SCIM
        // defines is how "fasle" becomes a deprovision again.
        return match (is_string($value) ? strtolower(trim($value)) : $value) {
            'true' => true,
            'false' => false,
            default => null,
        };
    }
}
