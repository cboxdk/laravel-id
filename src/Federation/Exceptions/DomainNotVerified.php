<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * Capture routes every sign-in on an email domain to one organization's connection,
 * so it may only be switched on for a domain whose DNS challenge was answered.
 *
 * Without proof of ownership, enabling capture on someone else's domain hands their
 * users' logins to your identity provider.
 */
class DomainNotVerified extends RuntimeException
{
    public static function make(string $domain): self
    {
        return new self("Domain [{$domain}] is not verified — capture cannot be enabled until the DNS challenge is answered.");
    }
}
