<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * A domain can back at most one organization within an environment — otherwise
 * two tenants could both claim `acme.com` and fight over home-realm routing.
 * Thrown once another organization has VERIFIED it; a pending claim is not ownership.
 */
class DomainAlreadyClaimed extends RuntimeException
{
    public static function make(string $domain): self
    {
        return new self("Domain [{$domain}] is already verified by another organization.");
    }
}
