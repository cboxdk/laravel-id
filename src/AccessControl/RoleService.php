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

final class RoleService implements Roles
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function define(?string $organizationId, string $name, ?string $description = null): Role
    {
        return Role::query()->firstOrCreate(
            ['organization_id' => $organizationId, 'name' => $name],
            ['description' => $description],
        );
    }

    public function grantPermission(string $organizationId, string $roleId, string $permission): void
    {
        // The role must belong to the caller's org — never grant onto another
        // tenant's role.
        $exists = Role::query()
            ->whereKey($roleId)
            ->where('organization_id', $organizationId)
            ->exists();

        if (! $exists) {
            throw UnknownRole::make($roleId);
        }

        $model = Permission::query()->firstOrCreate(['name' => $permission]);

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
