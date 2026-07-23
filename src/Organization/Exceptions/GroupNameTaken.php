<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

/**
 * Group names are unique per organization — a duplicate is refused explicitly
 * rather than surfacing as a database constraint violation.
 */
class GroupNameTaken extends RuntimeException
{
    public static function make(string $organizationId, string $name): self
    {
        return new self("Organization [{$organizationId}] already has a group named [{$name}].");
    }
}
