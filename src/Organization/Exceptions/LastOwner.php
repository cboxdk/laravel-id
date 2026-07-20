<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

/**
 * Guards the invariant that an organization always has at least one owner: the
 * sole owner cannot be demoted or removed (that would orphan the org).
 */
class LastOwner extends RuntimeException
{
    public static function make(string $organizationId): self
    {
        return new self("Organization [{$organizationId}] must keep at least one owner.");
    }
}
