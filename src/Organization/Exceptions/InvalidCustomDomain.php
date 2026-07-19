<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use InvalidArgumentException;

/**
 * Thrown when a requested environment custom domain is refused: a malformed
 * hostname, a bare IP, a domain reserved by the platform (a configured base
 * domain or its subdomains), or one already claimed by another environment.
 * Deny-by-default — the IdP never advertises an issuer host it has not validated.
 */
final class InvalidCustomDomain extends InvalidArgumentException
{
    public static function malformed(string $domain): self
    {
        return new self('not a valid domain name: '.$domain);
    }

    public static function reserved(string $domain): self
    {
        return new self('this domain is managed by the platform and cannot be used as a custom domain: '.$domain);
    }

    public static function taken(string $domain): self
    {
        return new self('this domain is already in use by another environment: '.$domain);
    }
}
