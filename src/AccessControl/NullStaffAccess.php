<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\StaffAccess;

/**
 * Deny-by-default {@see StaffAccess} for the 'external' RBAC driver: nobody holds any
 * staff capability until the host binds an adapter over its own authorization backend.
 */
class NullStaffAccess implements StaffAccess
{
    public function holdsEverywhere(string $userId, string $permission, string $clientId): bool
    {
        return false;
    }
}
