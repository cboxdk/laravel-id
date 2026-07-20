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
        $assignment = RoleAssignment::query()->firstOrCreate(
            ['organization_id' => $organizationId, 'user_id' => $userId, 'role_id' => $roleId],
            ['source' => $source],
        );

        $this->emitAndAudit($organizationId, $userId, $roleId, 'role.assigned');

        return $assignment;
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
