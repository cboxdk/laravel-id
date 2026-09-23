<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

/**
 * Guards the invariant that an organization always has at least one owner: the
 * sole owner cannot be demoted, removed, or leave (that would orphan the org).
 */
class LastOwner extends RuntimeException
{
    public static function make(string $organizationId): self
    {
        return new self("Organization [{$organizationId}] must keep at least one owner.");
    }

    /**
     * The refusal a person sees when they try to leave an organization they are the only
     * owner of. Worded as what to do next rather than as the invariant, because the person
     * reading it is the one who has to act: either hand the organization to somebody, or
     * archive it.
     */
    public static function leaving(string $organizationId): self
    {
        return new self(
            "You are the only owner of organization [{$organizationId}], so you cannot leave it. "
            .'Transfer ownership to another member first, or archive the organization.',
        );
    }
}
