<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\StaffAccess;
use Cbox\Id\AccessControl\Models\EnvironmentRoleAssignment;
use Cbox\Id\AccessControl\Models\Role;
use Illuminate\Support\Facades\DB;

/**
 * {@see StaffAccess} over the built-in RBAC tables.
 *
 * Every condition is bound into the one query rather than checked on loaded rows, so no
 * caller-side scope can make it pass: the grant must be environment-wide, its role must
 * belong to no organization and to this app or none, neither the role nor the permission
 * may be orphaned, and the permission must be declared by this app.
 */
class DatabaseStaffAccess implements StaffAccess
{
    public function holdsEverywhere(string $userId, string $permission, string $clientId): bool
    {
        $roleIds = EnvironmentRoleAssignment::query()
            ->where('user_id', $userId)
            ->whereIn('role_id', Role::query()
                ->select('id')
                ->whereNull('organization_id')
                ->whereNull('orphaned_at')
                ->where(fn ($query) => $query->whereNull('client_id')->orWhere('client_id', $clientId)))
            ->pluck('role_id')
            ->all();

        if ($roleIds === []) {
            return false;
        }

        return DB::table('role_permission')
            ->join('permissions', 'permissions.id', '=', 'role_permission.permission_id')
            ->whereIn('role_permission.role_id', $roleIds)
            ->where('permissions.name', $permission)
            ->where('permissions.client_id', $clientId)
            ->whereNull('permissions.orphaned_at')
            ->exists();
    }
}
