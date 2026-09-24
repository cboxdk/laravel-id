<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

/**
 * A self-service action only an organization's owner may take — archiving it — was
 * attempted by somebody who is not an active owner of it.
 */
class NotOrganizationOwner extends RuntimeException
{
    public static function make(string $organizationId, string $userId): self
    {
        return new self("User [{$userId}] is not an active owner of organization [{$organizationId}].");
    }
}
