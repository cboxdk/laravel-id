<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use RuntimeException;

/**
 * Thrown when an inbound SAML `LogoutRequest` is rejected: malformed XML, a missing
 * issuer or id, an unknown/disabled service provider, a required-but-absent or
 * invalid signature, or an SP with no registered SLO endpoint to answer. The
 * LogoutRequest is the security boundary for Single Logout, so an unverifiable one
 * is refused outright — never processed on trust. Never carries the raw payload.
 */
final class InvalidLogoutRequest extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('invalid LogoutRequest: '.$reason);
    }
}
