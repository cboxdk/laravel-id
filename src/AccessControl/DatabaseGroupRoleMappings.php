<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\GrantRefused;
use Cbox\Id\AccessControl\Models\GroupRoleMapping;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;

/**
 * Directory-group → role mappings + the reconciliation that keeps the derived
 * ("pushed") assignments in sync with group membership. Manual/system assignments
 * are never touched, so an admin's hand-granted role always survives a directory sync.
 */
class DatabaseGroupRoleMappings implements GroupRoleMappings
{
    public function __construct(
        private readonly Roles $roles,
        private readonly AuditLog $audit,
    ) {}

    public function map(string $organizationId, string $groupId, string $roleId, int $priority = 0): GroupRoleMapping
    {
        // Refuse a role this org may not assign BEFORE writing the mapping row.
        //
        // RoleService::assign() already blocks the escalation itself, but it is reached
        // only during reconciliation — several statements after the mapping is committed,
        // and outside any transaction. A foreign role id therefore left a poison-pill row
        // behind: the write succeeded, reconciliation threw, and every later reconcile of
        // that group (including ordinary directory syncs for unrelated members) threw
        // again on the same row. Validating here keeps the failure at the point of the
        // mistake instead of turning it into a permanently stuck sync.
        $this->roles->assertAssignableIn($organizationId, $roleId);

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

        // Drop mapped ids that no longer resolve to a role this org may assign, rather
        // than letting assign() throw on one of them.
        //
        // A reconcile is not a user action: it runs from a directory sync and from the
        // relay's `role.*` listener, where a throw releases the outbox claim and the
        // event is retried on every pass forever — never dispatched, never prunable, and
        // blocking every listener registered after this one. One stale row must not be
        // able to do that. map() refuses a foreign role up front and deleteRole() now
        // removes the mappings with the role, so reaching this is already a repair; the
        // roles simply drop out of the desired set, and anything still held via the
        // directory for them is unassigned below, which is the correct end state.
        $mappedRoleIds = $this->assignableOnly($organizationId, $mappedRoleIds);

        // Roles they currently hold VIA the directory (pushed only — manual/system
        // grants are the admin's, never reconciled away).
        $currentPushed = $this->stringIds(RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->where('source', GrantSource::Pushed->value)
            ->pluck('role_id')
            ->all());

        foreach (array_diff($mappedRoleIds, $currentPushed) as $roleId) {
            try {
                $this->roles->assign($organizationId, $userId, $roleId, GrantSource::Pushed);
            } catch (GrantRefused $refused) {
                // A conflict rule vetoed this one. Skip it and keep going: one person's
                // upstream group membership producing a forbidden pair must not abandon
                // the rest of the directory's sync. The refusal is audited, so it is
                // reviewable — a grant that silently does not happen is its own problem.
                $this->audit->record(new AuditEvent(
                    action: 'role.grant_withheld',
                    actorType: ActorType::System,
                    organizationId: $organizationId,
                    targetType: 'user',
                    targetId: $userId,
                    context: ['role_id' => $roleId, 'source' => GrantSource::Pushed->value, 'reason' => $refused->getMessage()],
                ));
            }
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

    /**
     * The subset of `$roleIds` this organization may actually be granted — its own roles
     * plus environment-wide system roles. Anything else is reported and dropped.
     *
     * @param  list<string>  $roleIds
     * @return list<string>
     */
    private function assignableOnly(string $organizationId, array $roleIds): array
    {
        if ($roleIds === []) {
            return [];
        }

        $assignable = $this->stringIds(Role::query()
            ->whereIn('id', $roleIds)
            ->where(fn ($query) => $query
                ->whereNull('organization_id')
                ->orWhere('organization_id', $organizationId))
            ->pluck('id')
            ->all());

        $dropped = array_values(array_diff($roleIds, $assignable));

        if ($dropped !== []) {
            Log::warning('cbox-id: directory group→role mapping names a role this organization cannot be granted; skipping it.', [
                'organization_id' => $organizationId,
                'role_ids' => $dropped,
            ]);
        }

        return $assignable;
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
