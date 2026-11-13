<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Models\EnvironmentRoleAssignment;
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

    public function forToken(string $userId, ?string $organizationId, string $clientId): AppAccessClaims
    {
        $roleIds = $this->roleIdsFor($userId, $organizationId);

        if ($roleIds === []) {
            return new AppAccessClaims([], []);
        }

        // Only roles relevant to THIS app: org-wide roles (client_id null) plus the
        // app's own declared roles. Another app's roles never leak into this token.
        //
        // THIS IS THE FILTER FOR BOTH KINDS OF GRANT. roleIdsFor() returns org-scoped and
        // environment-wide role ids together, and an environment-wide grant may now name
        // one app's declared role (a staff "Support" role an app ships), so this single
        // predicate is what keeps cadastre's staff role out of the tax app's token. It
        // runs on the union deliberately: one filter in one place, rather than a second
        // copy on the environment half that could drift from the first.
        $roles = Role::query()
            ->whereIn('id', $roleIds)
            ->where(function ($query) use ($clientId): void {
                $query->whereNull('client_id')->orWhere('client_id', $clientId);
            })
            ->get();

        if ($roles->isEmpty()) {
            return new AppAccessClaims([], []);
        }

        // A NAME THE APP DECLARES IS THE APP'S. Both claims are bare strings, and an
        // organization's own roles and permissions share their namespace with the app's
        // declared ones. A manual row spelled like an app's key would read to the app as
        // that key, and walk around `tenant_assignable`, which is how an app keeps a
        // privileged key off the tenant plane. So a name the app declares is emitted only
        // from the app's own declared row; any other row spelled the same (compared
        // case-insensitively) is dropped. An orphaned declaration still counts, since the
        // app may declare it again. Read without the model scopes, so an environment
        // context that hides the app's rows cannot make the check pass by omission.
        $declaredRoleKeys = $this->lowered(DB::table('roles')
            ->where('client_id', $clientId)
            ->whereNotNull('key')
            ->pluck('key')
            ->all());

        // A stable identifier per role: an app role's slug, else the role name.
        $roleKeys = array_values(array_unique(
            $roles
                ->filter(fn (Role $role): bool => $role->client_id === $clientId
                    || ! isset($declaredRoleKeys[mb_strtolower($role->key ?? $role->name)]))
                ->map(fn (Role $role): string => $role->key ?? $role->name)
                ->all()
        ));

        $rows = DB::table('role_permission')
            ->join('permissions', 'permissions.id', '=', 'role_permission.permission_id')
            ->whereIn('role_permission.role_id', $roles->modelKeys())
            ->distinct()
            ->get(['permissions.name', 'permissions.client_id']);

        $declaredPermissions = $this->lowered(DB::table('permissions')
            ->where('client_id', $clientId)
            ->pluck('name')
            ->all());

        $permissions = [];

        foreach ($rows as $row) {
            if (! is_string($row->name)) {
                continue;
            }

            if ($row->client_id === $clientId || ! isset($declaredPermissions[mb_strtolower($row->name)])) {
                $permissions[] = $row->name;
            }
        }

        $permissions = array_values(array_unique($permissions));

        // Sorted, byte-wise, in PHP. Both claims are sets, but they are signed into a
        // token and compared by apps, SDK caches and tests: an order that depends on the
        // engine's row order (PostgreSQL and SQLite disagreed) or its collation is an
        // order nobody can rely on. SORT_STRING is the same everywhere.
        sort($roleKeys, SORT_STRING);
        sort($permissions, SORT_STRING);

        return new AppAccessClaims($roleKeys, $permissions);
    }

    /**
     * A lookup set of the given names, lower-cased.
     *
     * @param  array<mixed>  $names
     * @return array<string, true>
     */
    private function lowered(array $names): array
    {
        $set = [];

        foreach ($names as $name) {
            if (is_string($name)) {
                $set[mb_strtolower($name)] = true;
            }
        }

        return $set;
    }

    /**
     * Role ids assigned to the user in the org or any of its ancestors.
     *
     * @return list<string>
     */
    /**
     * @param  string|null  $organizationId  null asks only what is held environment-wide
     * @return list<string>
     */
    private function roleIdsFor(string $userId, ?string $organizationId): array
    {
        $scopes = $organizationId === null
            ? []
            : array_merge([$organizationId], $this->hierarchy->ancestors($organizationId));

        // ENVIRONMENT-WIDE GRANTS APPLY IN EVERY ORGANIZATION, which is the whole point
        // of them: a support agent acting across every customer holds the role once, not
        // once per tenant. They are unioned with the org grants rather than replacing
        // them, so somebody can hold Support everywhere AND Editor in one place.
        //
        // THE SAME DEFENSE THE ORG HALF HAS, for the same reason. This half used to
        // decline it on the grounds that assignEverywhere() only writes eligible roles —
        // true today, and exactly the reasoning the org half's own comment rejects. One
        // raw write from host code, a future console action, or the class of bug that
        // comment describes would put a tenant's role into EVERY organization's tokens,
        // silently. It costs one subquery to make both halves tell the same story.
        //
        // No `client_id` predicate here any more: an app's own declared role may be held
        // environment-wide (a staff role), and which APP it reaches is forToken()'s
        // question, answered there for both halves at once.
        $everywhere = array_values(array_filter(
            EnvironmentRoleAssignment::query()
                ->where('user_id', $userId)
                ->whereIn('role_id', Role::query()
                    ->select('id')
                    ->whereNull('organization_id'))
                ->pluck('role_id')
                ->all(),
            'is_string',
        ));

        $inOrg = $scopes === [] ? [] : array_values(
            RoleAssignment::query()
                ->where('user_id', $userId)
                ->whereIn('organization_id', $scopes)
                // Defense in depth: trust the ROLE's own owner, not just the assignment
                // row's. An assignment naming another tenant's role — however the row came
                // to exist — must never surface that role's permissions here. RoleService
                // refuses to write such a row; this makes reading one harmless too, and it
                // covers all three entry points (can, permissionsFor, forToken) at once.
                // Role is environment-scoped, so the subquery also keeps the env boundary.
                ->whereIn('role_id', Role::query()
                    ->select('id')
                    ->where(fn ($query) => $query
                        ->whereNull('organization_id')
                        ->orWhereIn('organization_id', $scopes)))
                ->get()
                ->map(fn (RoleAssignment $assignment): string => $assignment->role_id)
                ->all()
        );

        return array_values(array_unique([...$inOrg, ...$everywhere]));
    }
}
