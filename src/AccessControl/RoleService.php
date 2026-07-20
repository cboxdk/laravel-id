<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
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

        $assignment = RoleAssignment::query()->firstOrCreate(
            ['organization_id' => $organizationId, 'user_id' => $userId, 'role_id' => $roleId],
            ['source' => $source],
        );

        $this->emitAndAudit($organizationId, $userId, $roleId, 'role.assigned');

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
        RoleAssignment::query()
            ->where('organization_id', $organizationId)
            ->where('user_id', $userId)
            ->where('role_id', $roleId)
            ->delete();

        $this->emitAndAudit($organizationId, $userId, $roleId, 'role.unassigned');
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
