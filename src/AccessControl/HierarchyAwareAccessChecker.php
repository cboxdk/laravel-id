<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Illuminate\Support\Facades\DB;

/**
 * Resolves RBAC permissions across the org and its ancestors, so a role granted
 * at a reseller/parent rolls down to the descendants it manages.
 */
final class HierarchyAwareAccessChecker implements AccessChecker
{
    public function __construct(private readonly OrganizationHierarchy $hierarchy) {}

    public function can(string $userId, string $permission, string $organizationId): bool
    {
        $roleIds = $this->roleIdsFor($userId, $organizationId);

        if ($roleIds === []) {
            return false;
        }

        $permissionId = Permission::query()->where('name', $permission)->value('id');

        if (! is_string($permissionId)) {
            return false;
        }

        return DB::table('role_permission')
            ->whereIn('role_id', $roleIds)
            ->where('permission_id', $permissionId)
            ->exists();
    }

    public function permissionsFor(string $userId, string $organizationId): array
    {
        $roleIds = $this->roleIdsFor($userId, $organizationId);

        if ($roleIds === []) {
            return [];
        }

        $names = DB::table('role_permission')
            ->join('permissions', 'permissions.id', '=', 'role_permission.permission_id')
            ->whereIn('role_permission.role_id', $roleIds)
            ->distinct()
            ->pluck('permissions.name')
            ->all();

        return array_values(array_filter($names, 'is_string'));
    }

    /**
     * Role ids assigned to the user in the org or any of its ancestors.
     *
     * @return list<string>
     */
    private function roleIdsFor(string $userId, string $organizationId): array
    {
        $scopes = array_merge([$organizationId], $this->hierarchy->ancestors($organizationId));

        return array_values(
            RoleAssignment::query()
                ->where('user_id', $userId)
                ->whereIn('organization_id', $scopes)
                ->get()
                ->map(fn (RoleAssignment $assignment): string => $assignment->role_id)
                ->all()
        );
    }
}
