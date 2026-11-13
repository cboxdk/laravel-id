<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

/**
 * Inflates a SAML HTTP-Redirect binding payload (raw DEFLATE, SAML bindings §3.4.4.1),
 * with a ceiling on the output.
 *
 * DEFLATE compresses a run of one byte about a thousandfold, and these messages arrive
 * before anyone has signed in: without a ceiling, a SAMLRequest of a few dozen kilobytes
 * makes the worker allocate tens of megabytes, or a gigabyte where `memory_limit` allows
 * it. A real AuthnRequest or LogoutRequest is a few kilobytes, so one mebibyte is far
 * beyond any genuine message; anything larger is refused like any other undecodable one.
 */
final class RedirectBindingInflater
{
    public const int MAX_BYTES = 1024 * 1024;

    /** The inflated message, or null when it is not raw DEFLATE or inflates past the ceiling. */
    public static function inflate(string $deflated): ?string
    {
        // gzinflate() warns and returns false on bad input and on output past the limit.
        // The limit is enforced a buffer round at a time, so it can return a little more:
        // the allocation is bounded either way, and the length is checked exactly here.
        $inflated = @gzinflate($deflated, self::MAX_BYTES);

        return is_string($inflated) && $inflated !== '' && strlen($inflated) <= self::MAX_BYTES ? $inflated : null;
    }
}
