<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Models\GroupRoleMapping;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Illuminate\Support\Facades\DB;

/**
 * Directory-group → role mappings + the reconciliation that keeps the derived
 * ("pushed") assignments in sync with group membership. Manual/system assignments
 * are never touched, so an admin's hand-granted role always survives a directory sync.
 */
final class DatabaseGroupRoleMappings implements GroupRoleMappings
{
    public function __construct(private readonly Roles $roles) {}

    public function map(string $organizationId, string $groupId, string $roleId, int $priority = 0): GroupRoleMapping
    {
        $mapping = GroupRoleMapping::query()->updateOrCreate(
            ['organization_id' => $organizationId, 'group_id' => $groupId, 'role_id' => $roleId],
            ['priority' => $priority],
        );

        // A mapping change takes effect immediately for everyone in the group.
        $this->reconcileGroup($groupId);

        return $mapping;
    }

    public function unmap(string $organizationId, string $groupId, string $roleId): void
    {
        GroupRoleMapping::query()
            ->where('organization_id', $organizationId)
            ->where('group_id', $groupId)
            ->where('role_id', $roleId)
            ->delete();

        $this->reconcileGroup($groupId);
    }

    public function forOrganization(string $organizationId): array
    {
        return array_values(GroupRoleMapping::query()
            ->where('organization_id', $organizationId)
            ->orderByDesc('priority')
            ->get()
            ->all());
    }

    public function reconcileUser(string $organizationId, string $userId): void
    {
        $memberGroupIds = $this->groupIdsForUser($organizationId, $userId);

        // Roles the user SHOULD hold via the directory, from their group memberships.
        $mappedRoleIds = $memberGroupIds === []
            ? []
            : $this->stringIds(GroupRoleMapping::query()
                ->where('organization_id', $organizationId)
                ->whereIn('group_id', $memberGroupIds)
                ->pluck('role_id')
                ->all());

        // Roles they currently hold VIA the directory (pushed only — manual/system
        // grants are the admin's, never reconciled away).
        $currentPushed = $this->stringIds(RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->where('source', GrantSource::Pushed->value)
            ->pluck('role_id')
            ->all());

        foreach (array_diff($mappedRoleIds, $currentPushed) as $roleId) {
            $this->roles->assign($organizationId, $userId, $roleId, GrantSource::Pushed);
        }

        foreach (array_diff($currentPushed, $mappedRoleIds) as $roleId) {
            $this->roles->unassign($organizationId, $userId, $roleId);
        }
    }

    public function reconcileGroup(string $groupId, ?string $organizationId = null): void
    {
        // The org is passed in when the group row is already gone (a delete); else
        // resolved from the group's directory.
        $organizationId ??= $this->organizationOf($groupId);

        if ($organizationId === null) {
            return;
        }

        // Reconcile the union of: who is in the group NOW (may GAIN a role) and who
        // currently holds one of this group's mapped roles via the directory (may
        // LOSE it if they're no longer a member). This makes reconcileGroup correct
        // for adds, removes, and group deletion alike, without tracking deltas.
        $currentMembers = $this->stringIds(DB::table('directory_group_members')
            ->join('directory_users', 'directory_users.id', '=', 'directory_group_members.directory_user_id')
            ->where('directory_group_members.group_id', $groupId)
            ->where('directory_users.active', true)
            ->whereNotNull('directory_users.user_id')
            ->pluck('directory_users.user_id')
            ->all());

        $mappedRoleIds = $this->stringIds(GroupRoleMapping::query()
            ->where('organization_id', $organizationId)
            ->where('group_id', $groupId)
            ->pluck('role_id')
            ->all());

        $priorHolders = $mappedRoleIds === []
            ? []
            : $this->stringIds(RoleAssignment::query()
                ->where('organization_id', $organizationId)
                ->where('source', GrantSource::Pushed->value)
                ->whereIn('role_id', $mappedRoleIds)
                ->pluck('user_id')
                ->all());

        foreach (array_unique([...$currentMembers, ...$priorHolders]) as $userId) {
            $this->reconcileUser($organizationId, $userId);
        }
    }

    private function organizationOf(string $groupId): ?string
    {
        $organizationId = DB::table('directory_groups')
            ->join('directories', 'directories.id', '=', 'directory_groups.directory_id')
            ->where('directory_groups.id', $groupId)
            ->value('directories.organization_id');

        return is_string($organizationId) ? $organizationId : null;
    }

    /**
     * @param  array<array-key, mixed>  $ids
     * @return list<string>
     */
    private function stringIds(array $ids): array
    {
        return array_values(array_unique(array_filter($ids, 'is_string')));
    }

    /**
     * Directory group ids the user belongs to within this org (active memberships).
     *
     * @return list<string>
     */
    private function groupIdsForUser(string $organizationId, string $userId): array
    {
        $ids = DB::table('directory_group_members')
            ->join('directory_users', 'directory_users.id', '=', 'directory_group_members.directory_user_id')
            ->join('directory_groups', 'directory_groups.id', '=', 'directory_group_members.group_id')
            ->join('directories', 'directories.id', '=', 'directory_groups.directory_id')
            ->where('directory_users.user_id', $userId)
            ->where('directory_users.active', true)
            ->where('directories.organization_id', $organizationId)
            ->distinct()
            ->pluck('directory_group_members.group_id')
            ->all();

        return array_values(array_filter($ids, 'is_string'));
    }
}
