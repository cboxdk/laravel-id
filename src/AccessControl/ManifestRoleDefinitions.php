<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\RoleDefinitions;
use Cbox\Id\AccessControl\Enums\RoleSource;
use Cbox\Id\AccessControl\Exceptions\RoleDefinitionChanged;
use Cbox\Id\AccessControl\Manifest\DeclaredRole;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Support\Facades\DB;

/** Publication discovers definitions; only an explicit activation changes existing access. */
class ManifestRoleDefinitions implements RoleDefinitions
{
    public function __construct(private readonly AuditLog $audit, private readonly EventBus $events) {}

    public function stage(Role $role, DeclaredRole $definition): void
    {
        DB::transaction(function () use ($role, $definition): void {
            $created = $role->wasRecentlyCreated;
            $locked = Role::query()->whereKey($role->id)->lockForUpdate()->firstOrFail();
            $this->stageLocked($locked, $definition, $created);
        });
    }

    private function stageLocked(Role $role, DeclaredRole $definition, bool $created): void
    {
        $desired = array_values(array_unique($definition->permissions));
        sort($desired);
        $current = $this->permissions($role);
        $version = $this->version($desired, $definition->tenantAssignable);

        if ($created) {
            $this->replacePermissions($role, $desired);
            $role->update(['active_definition_version' => $version, 'tenant_assignable' => $definition->tenantAssignable]);

            return;
        }

        if ($current === $desired && $role->tenant_assignable === $definition->tenantAssignable) {
            $role->update([
                'active_definition_version' => $version,
                'pending_definition_version' => null,
                'pending_permission_keys' => null,
                'pending_tenant_assignable' => null,
            ]);

            return;
        }

        $role->update([
            'pending_definition_version' => $version,
            'pending_permission_keys' => $desired,
            'pending_tenant_assignable' => $definition->tenantAssignable,
        ]);
    }

    /** The caller must authorize environment-level definition management before activation. */
    public function activate(string $roleId, string $expectedVersion, AuditActor $actor): Role
    {
        if (($actor->id === null || $actor->id === '') || $expectedVersion === '') {
            throw new RoleDefinitionChanged;
        }

        return DB::transaction(function () use ($roleId, $expectedVersion, $actor): Role {
            $role = Role::query()->whereKey($roleId)->where('source', RoleSource::Manifest->value)->whereNull('orphaned_at')->lockForUpdate()->first();

            if ($role === null || $role->pending_definition_version !== $expectedVersion
                || $role->pending_permission_keys === null || $role->pending_tenant_assignable === null) {
                throw new RoleDefinitionChanged;
            }

            $before = ['permissions' => $this->permissions($role), 'tenant_assignable' => $role->tenant_assignable];
            $after = ['permissions' => $role->pending_permission_keys, 'tenant_assignable' => $role->pending_tenant_assignable];
            $this->replacePermissions($role, $role->pending_permission_keys);
            $role->update([
                'tenant_assignable' => $role->pending_tenant_assignable,
                'active_definition_version' => $expectedVersion,
                'pending_definition_version' => null,
                'pending_permission_keys' => null,
                'pending_tenant_assignable' => null,
            ]);

            $this->audit->record(new AuditEvent(
                action: 'role.definition_activated', actorType: $actor->type, actorId: $actor->id,
                targetType: 'role', targetId: $role->id,
                context: ['client_id' => $role->client_id, 'version' => $expectedVersion, 'from' => $before, 'to' => $after],
            ));
            $this->events->emit(new DomainEvent('role.definition_activated', ['role_id' => $role->id, 'client_id' => $role->client_id, 'version' => $expectedVersion]));

            return $role;
        });
    }

    /** @return list<string> */
    private function permissions(Role $role): array
    {
        return array_values(Permission::query()->where('client_id', $role->client_id)
            ->whereIn('id', DB::table('role_permission')->where('role_id', $role->id)->select('permission_id'))
            ->orderBy('name')->get()->map(static fn (Permission $permission): string => $permission->name)->all());
    }

    /** @param list<string> $keys */
    private function version(array $keys, bool $tenantAssignable): string
    {
        return hash('sha256', json_encode(['permissions' => $keys, 'tenant_assignable' => $tenantAssignable], JSON_THROW_ON_ERROR));
    }

    /** @param list<string> $keys */
    private function replacePermissions(Role $role, array $keys): void
    {
        $permissions = Permission::query()->where('client_id', $role->client_id)->whereIn('name', $keys)->whereNull('orphaned_at')->get();

        if ($permissions->count() !== count($keys)) {
            throw new RoleDefinitionChanged;
        }

        DB::table('role_permission')->where('role_id', $role->id)->delete();
        foreach ($permissions as $permission) {
            DB::table('role_permission')->insert(['role_id' => $role->id, 'permission_id' => $permission->id]);
        }
    }
}
