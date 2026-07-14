<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * A domain can back at most one organization within an environment — otherwise
 * two tenants could both claim `acme.com` and fight over home-realm routing.
 */
final class DomainAlreadyClaimed extends RuntimeException
{
    public static function make(string $domain): self
    {
        return new self("Domain [{$domain}] is already claimed by another organization.");
    }
}
