<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\GrantGuard;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\GrantRefused;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\GroupRoleMapping;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Support\Facades\DB;

class RoleService implements Roles
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
        private readonly GrantGuard $grants,
    ) {}

    public function define(?string $organizationId, string $name, ?string $description = null, ?string $clientId = null): Role
    {
        return Role::query()->firstOrCreate(
            ['organization_id' => $organizationId, 'client_id' => $clientId, 'name' => $name],
            ['description' => $description],
        );
    }

    public function grantPermission(string $organizationId, string $roleId, string $permission): void
    {
        // The role must belong to the caller's org — never grant onto another
        // tenant's role.
        $role = Role::query()
            ->whereKey($roleId)
            ->where('organization_id', $organizationId)
            ->first();

        if ($role === null) {
            throw UnknownRole::make($roleId);
        }

        // Resolve the permission WITHIN the role's own scope. An app-scoped role's
        // permissions live under that app's client_id; an org-wide role's under
        // client_id null. Matching on (client_id, name) — the table's unique key —
        // means we reuse the app's declared permission instead of minting a stray
        // client_id-null duplicate of it (the old firstOrCreate(['name']) bug).
        $model = Permission::query()->firstOrCreate([
            'client_id' => $role->client_id,
            'name' => $permission,
        ]);

        DB::table('role_permission')->insertOrIgnore([
            'role_id' => $roleId,
            'permission_id' => $model->id,
        ]);
    }

    public function updateRole(string $roleId, string $name, ?string $description = null): Role
    {
        $role = $this->requireRole($roleId);

        $before = ['name' => $role->name, 'description' => $role->description];

        $role->name = $name;
        $role->description = $description;
        $role->save();

        $this->recordRoleChange($role, 'role.updated', ['from' => $before, 'to' => ['name' => $name, 'description' => $description]]);

        return $role;
    }

    public function attachPermission(string $roleId, string $permissionId): void
    {
        $role = $this->requireRole($roleId);

        $attached = DB::table('role_permission')->insertOrIgnore([
            'role_id' => $role->id,
            'permission_id' => $permissionId,
        ]);

        // Announce a STATE CHANGE, not a call — the same rule assign() follows.
        if ($attached > 0) {
            $this->recordRoleChange($role, 'role.permission_granted', ['permission_id' => $permissionId]);
        }
    }

    public function revokePermission(string $roleId, string $permissionId): void
    {
        $role = $this->requireRole($roleId);

        $detached = DB::table('role_permission')
            ->where('role_id', $role->id)
            ->where('permission_id', $permissionId)
            ->delete();

        if ($detached > 0) {
            $this->recordRoleChange($role, 'role.permission_revoked', ['permission_id' => $permissionId]);
        }
    }

    public function deleteRole(string $roleId): void
    {
        $role = $this->requireRole($roleId);

        // One transaction for the whole removal, and for the events it announces.
        //
        // Nothing here cascades at the database layer, so a partial delete is a
        // half-removed role: rows pointing at an id that no longer resolves, with no
        // second pass to finish the job. The outbox rows are written inside it too — the
        // same rule MembershipService::add() follows — so a crash cannot leave the grants
        // gone and the `role.unassigned` events unwritten.
        DB::transaction(function () use ($role): void {
            // Read the holders BEFORE the delete: they are the subjects whose privileges
            // this removes, and the only way a downstream mirror can be told which grants
            // went. Nothing else reports them — there is no FK cascade and no observer.
            $held = RoleAssignment::query()->where('role_id', $role->id)->get();

            DB::table('role_permission')->where('role_id', $role->id)->delete();

            // The directory group→role mappings MUST go with the role. `group_role_mappings`
            // has neither a foreign key nor a cascade, so a surviving mapping keeps naming a
            // role id that no longer resolves — and the next reconcile of that group plucks
            // it, calls assign(), and assertAssignableIn() throws UnknownRole. That is the
            // exact poison-pill this class's map() docblock says it fixed, reintroduced from
            // the other end: the reconcile runs on the RELAY, whose isolation releases the
            // claim and retries the event forever, so the outbox row can never be pruned and
            // every listener registered after AccessControl — webhooks, provisioning, usage
            // metering, audit streaming — is skipped for that event on every pass.
            GroupRoleMapping::query()->where('role_id', $role->id)->delete();

            RoleAssignment::query()->where('role_id', $role->id)->delete();
            $role->delete();

            // One `role.unassigned` per holder, exactly as unassign() emits, so a consumer
            // reconciling grants off that event learns the role is gone from each subject.
            $userIds = [];
            foreach ($held as $assignment) {
                $userIds[] = $assignment->user_id;
                $this->emitAndAudit($assignment->organization_id, $assignment->user_id, $role->id, 'role.unassigned');
            }

            $userIds = array_values(array_unique($userIds));

            $this->recordRoleChange($role, 'role.deleted', [
                'name' => $role->name,
                'client_id' => $role->client_id,
                'user_ids' => $userIds,
            ]);
        });
    }

    /**
     * @throws UnknownRole
     */
    private function requireRole(string $roleId): Role
    {
        $role = Role::query()->whereKey($roleId)->first();

        if ($role === null) {
            throw UnknownRole::make($roleId);
        }

        return $role;
    }

    /**
     * Emit + audit a change to the role CATALOG. Mirrors {@see emitAndAudit()}, but
     * the target is the role rather than a subject, and the tenant tag is the role's
     * own organization (null for an environment-wide role, which records on the
     * system trail).
     *
     * @param  array<string, mixed>  $context
     */
    private function recordRoleChange(Role $role, string $action, array $context = []): void
    {
        $this->events->emit(new DomainEvent(
            $action,
            ['role_id' => $role->id] + $context,
            $role->organization_id,
        ));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            organizationId: $role->organization_id,
            targetType: 'role',
            targetId: $role->id,
            context: $context,
        ));
    }

    public function assign(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): RoleAssignment {
        // The role must be assignable IN this organization — either its own, or a system
        // role (organization_id null) shared across the environment. This is the chokepoint
        // every caller funnels through — console toggles, directory group→role mapping and
        // invitation grants all land here — so validating once closes all of them. Without
        // it a caller can name ANOTHER tenant's role id and have it written under their own
        // org, and the read path would then surface that role's permissions in this org's
        // tokens. Mirrors the ownership check grantPermission() has always had.
        $this->assertAssignableIn($organizationId, $roleId);

        // Conflict rules, at the same chokepoint as ownership. These used to be enforced
        // only by the host, in front of the console's manual grant paths — and the one
        // path a host cannot get in front of is this one, so a directory group→role
        // mapping created toxic pairs the console would have refused, silently, on every
        // reconcile. The automation a customer buys is not a way around the control they
        // bought. Via a contract because Governance already depends on AccessControl and
        // a direct dependency back would close a cycle.
        $refusal = $this->grants->refuse($organizationId, $userId, $roleId, $source);

        if ($refusal !== null) {
            throw new GrantRefused($organizationId, $userId, $roleId, $refusal);
        }

        $assignment = RoleAssignment::query()->firstOrCreate(
            ['organization_id' => $organizationId, 'user_id' => $userId, 'role_id' => $roleId],
            ['source' => $source],
        );

        // Announce a STATE CHANGE, not a call. Re-assigning a role the user already
        // holds is a no-op on the row, and emitting anyway made every reconcile pass
        // write an outbox row plus a hash-chained audit entry per user.
        //
        // The directory reconciler makes that constant: it compares the mapped roles
        // against the assignments whose source is `pushed`, so a user holding a mapped
        // role via a MANUAL grant is never in that set and is "assigned" again on every
        // single reconcile — burning a relay slot each time and feeding the very relay
        // backlog the async webhook work exists to keep short.
        if ($assignment->wasRecentlyCreated) {
            $this->emitAndAudit($organizationId, $userId, $roleId, 'role.assigned');
        }

        return $assignment;
    }

    /**
     * A role belongs to this organization, or is a system role usable by any org in the
     * environment. Anything else is another tenant's policy and is refused.
     *
     * Public so callers that write a role id somewhere OTHER than an assignment row —
     * directory group→role mappings, for one — can refuse it up front rather than
     * discovering it later during reconciliation.
     *
     * @throws UnknownRole
     */
    public function assertAssignableIn(string $organizationId, string $roleId): void
    {
        $assignable = Role::query()
            ->whereKey($roleId)
            ->where(fn ($query) => $query
                ->whereNull('organization_id')
                ->orWhere('organization_id', $organizationId))
            ->exists();

        if (! $assignable) {
            throw UnknownRole::make($roleId);
        }
    }

    public function unassign(string $organizationId, string $userId, string $roleId): void
    {
        $deleted = RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->where('role_id', $roleId)
            ->delete();

        // Same rule as assign(): revoking a role the user does not hold changed
        // nothing, so it announces nothing.
        if ($deleted > 0) {
            $this->emitAndAudit($organizationId, $userId, $roleId, 'role.unassigned');
        }
    }

    public function unassignAll(string $organizationId, string $userId): int
    {
        $roleIds = RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->pluck('role_id')
            ->all();

        if ($roleIds === []) {
            return 0;
        }

        RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->delete();

        // One event per role, not one for the batch: a downstream consumer reconciling
        // grants needs to know WHICH roles went, and every other revocation on this
        // service reports itself that way.
        foreach ($roleIds as $roleId) {
            if (is_string($roleId)) {
                $this->emitAndAudit($organizationId, $userId, $roleId, 'role.unassigned');
            }
        }

        return count($roleIds);
    }

    public function assignmentsForSubject(string $organizationId, string $userId): array
    {
        return array_values(RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->get()
            ->all());
    }

    public function assignmentsInOrganization(string $organizationId): array
    {
        return array_values(RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->orderBy('user_id')
            ->get()
            ->all());
    }

    private function emitAndAudit(string $organizationId, string $userId, string $roleId, string $action): void
    {
        $this->events->emit(new DomainEvent($action, ['user_id' => $userId, 'role_id' => $roleId], $organizationId));

        $this->audit->record(new AuditEvent(
            action: $action,
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: 'user',
            targetId: $userId,
            context: ['role_id' => $roleId],
        ));
    }
}
