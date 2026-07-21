<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * An OpenID Provider's discovery document could not be turned into a usable
 * connection prefill — the URL was unreachable, returned an error, was not JSON,
 * advertised an issuer that did not match, or omitted the authorization/token
 * endpoint the OIDC client requires.
 */
class OidcDiscoveryFailed extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('Could not discover the OpenID Provider: '.$reason);
    }
}
