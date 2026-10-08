<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

/**
 * An authorization request whose `max_age` or `acr_values` cannot be read.
 *
 * Carries the OAuth error code the authorization (or PAR) endpoint returns verbatim:
 * always `invalid_request` (RFC 6749 §4.1.2.1). `max_age` is a demand about how recent
 * the login must be; a value that is not a non-negative integer (OIDC Core §3.1.2.1,
 * RFC 9470 §3) cannot be honoured, and quietly dropping it would hand the client a token
 * minted from a login it explicitly asked not to accept.
 */
class InvalidAuthenticationRequirement extends RuntimeException
{
    public readonly string $error;

    public function __construct(string $message)
    {
        parent::__construct($message);

        $this->error = 'invalid_request';
    }

    public static function malformedMaxAge(): self
    {
        return new self('max_age must be a non-negative integer number of seconds.');
    }

    public static function malformedAcrValues(): self
    {
        return new self('acr_values must be a space-separated string of authentication context class references.');
    }
}
