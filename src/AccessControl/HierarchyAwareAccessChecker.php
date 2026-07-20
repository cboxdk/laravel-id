<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\AccessControl\ValueObjects\AppAccessClaims;
use Cbox\Id\Organization\Contracts\OrganizationHierarchy;
use Illuminate\Support\Facades\DB;

/**
 * Resolves RBAC permissions across the org and its ancestors, so a role granted
 * at a reseller/parent rolls down to the descendants it manages.
 */
class HierarchyAwareAccessChecker implements AccessChecker
{
    public function __construct(private readonly OrganizationHierarchy $hierarchy) {}

    public function can(string $userId, string $permission, string $organizationId): bool
    {
        $roleIds = $this->roleIdsFor($userId, $organizationId);

        if ($roleIds === []) {
            return false;
        }

        // Match by permission NAME via the pivot join — permission names are only
        // unique per declaring app now, so resolving name→id up front would be
        // ambiguous. "Does any assigned role grant a permission of this name?" is the
        // correct, unambiguous question.
        return DB::table('role_permission')
            ->join('permissions', 'permissions.id', '=', 'role_permission.permission_id')
            ->whereIn('role_permission.role_id', $roleIds)
            ->where('permissions.name', $permission)
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

    public function forToken(string $userId, string $organizationId, string $clientId): AppAccessClaims
    {
        $roleIds = $this->roleIdsFor($userId, $organizationId);

        if ($roleIds === []) {
            return new AppAccessClaims([], []);
        }

        // Only roles relevant to THIS app: org-wide roles (client_id null) plus the
        // app's own declared roles. Another app's roles never leak into this token.
        $roles = Role::query()
            ->whereIn('id', $roleIds)
            ->where(function ($query) use ($clientId): void {
                $query->whereNull('client_id')->orWhere('client_id', $clientId);
            })
            ->get();

        if ($roles->isEmpty()) {
            return new AppAccessClaims([], []);
        }

        // A stable identifier per role: an app role's slug, else the role name.
        $roleKeys = array_values(array_unique(
            $roles->map(fn (Role $role): string => $role->key ?? $role->name)->all()
        ));

        $permissions = DB::table('role_permission')
            ->join('permissions', 'permissions.id', '=', 'role_permission.permission_id')
            ->whereIn('role_permission.role_id', $roles->modelKeys())
            ->distinct()
            ->pluck('permissions.name')
            ->all();

        return new AppAccessClaims(
            $roleKeys,
            array_values(array_filter($permissions, 'is_string')),
        );
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
