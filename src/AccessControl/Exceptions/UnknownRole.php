<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Exceptions;

use RuntimeException;

/**
 * Thrown when a role operation targets a role that does not belong to the
 * organization it is scoped to — prevents cross-tenant policy tampering.
 */
final class UnknownRole extends RuntimeException
{
    public static function make(string $roleId): self
    {
        return new self("Role [{$roleId}] does not exist in this organization.");
    }
}
