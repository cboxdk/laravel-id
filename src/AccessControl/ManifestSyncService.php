<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Enums\RoleSource;
use Cbox\Id\AccessControl\Manifest\DeclaredRole;
use Cbox\Id\AccessControl\Manifest\Manifest;
use Cbox\Id\AccessControl\Manifest\ManifestSyncResult;
use Cbox\Id\AccessControl\Models\AppManifest;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Reconciles an app's declared catalog (roles + permissions) to match its manifest.
 * The reconciliation is idempotent and safe by construction: it only ever touches
 * rows scoped to the declaring app (client_id), never an assignment, and it flags —
 * rather than deletes — anything the app stops declaring, so a bad deploy can't
 * silently revoke someone's access.
 */
class ManifestSyncService implements AppManifests
{
    public function __construct(
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function sync(string $clientId, Manifest $manifest): ManifestSyncResult
    {
        $checksum = $manifest->checksum();
        $existing = $this->current($clientId);

        // Unchanged manifest → cheap no-op; pull/push/SDK can call this freely.
        if ($existing !== null && $existing->checksum === $checksum) {
            return ManifestSyncResult::unchanged();
        }

        $result = DB::transaction(function () use ($clientId, $manifest, $checksum): ManifestSyncResult {
            $this->syncPermissions($clientId, $manifest);
            $this->syncRoles($clientId, $manifest);

            $orphanedPermissions = $this->flagOrphanedPermissions($clientId, $manifest->permissionKeys());
            $orphanedRoles = $this->flagOrphanedRoles($clientId, $manifest->roleKeys());

            AppManifest::query()->updateOrCreate(
                ['client_id' => $clientId],
                ['version' => $manifest->version, 'checksum' => $checksum, 'synced_at' => now()],
            );

            return new ManifestSyncResult(
                unchanged: false,
                permissionsDeclared: count($manifest->permissions),
                rolesDeclared: count($manifest->roles),
                orphanedRoleKeys: $orphanedRoles,
                orphanedPermissionKeys: $orphanedPermissions,
            );
        });

        $this->events->emit(new DomainEvent('app.manifest_synced', [
            'client_id' => $clientId,
            'version' => $manifest->version,
            'permissions' => $result->permissionsDeclared,
            'roles' => $result->rolesDeclared,
            'orphaned_roles' => $result->orphanedRoleKeys,
        ]));

        $this->audit->record(new AuditEvent(
            action: 'app.manifest_synced',
            actorType: ActorType::System,
            targetType: 'client',
            targetId: $clientId,
            context: [
                'version' => $manifest->version,
                'roles' => $result->rolesDeclared,
                'permissions' => $result->permissionsDeclared,
                'orphaned_roles' => $result->orphanedRoleKeys,
                'orphaned_permissions' => $result->orphanedPermissionKeys,
            ],
        ));

        return $result;
    }

    public function current(string $clientId): ?AppManifest
    {
        return AppManifest::query()->where('client_id', $clientId)->first();
    }

    public function declaredRoles(string $clientId): array
    {
        return array_values(Role::query()
            ->where('client_id', $clientId)
            ->whereNull('orphaned_at')
            ->orderBy('name')
            ->get()
            ->all());
    }

    private function syncPermissions(string $clientId, Manifest $manifest): void
    {
        // A declared permission is scoped to its declaring app's environment. Derive
        // it from the CLIENT, not ambient context: the sync may run under a suspended
        // (or otherwise mismatched) tenancy scope, so resolve the client across the
        // boundary and stamp its environment on every declared row.
        $environmentId = $this->environmentForClient($clientId);

        foreach ($manifest->permissions as $permission) {
            Permission::query()->updateOrCreate(
                ['client_id' => $clientId, 'name' => $permission->key],
                [
                    'environment_id' => $environmentId,
                    'description' => $permission->description,
                    'tenant_assignable' => $permission->tenantAssignable,
                    'orphaned_at' => null,
                ],
            );
        }
    }

    /**
     * The environment of the declaring client, resolved across the environment scope
     * (the sync may run with tenancy scoping suspended). Null when the client is
     * unknown — the permission then stays platform-global, matching manual creation.
     */
    private function environmentForClient(string $clientId): ?string
    {
        $environmentId = app(EnvironmentContext::class)->withoutScope(
            fn (): mixed => Client::query()->where('client_id', $clientId)->value('environment_id'),
        );

        return is_string($environmentId) ? $environmentId : null;
    }

    private function syncRoles(string $clientId, Manifest $manifest): void
    {
        // Resolve declared permission keys → ids once for the pivot wiring.
        $permissionIds = Permission::query()
            ->where('client_id', $clientId)
            ->pluck('id', 'name');

        foreach ($manifest->roles as $role) {
            $model = Role::query()->updateOrCreate(
                ['client_id' => $clientId, 'key' => $role->key],
                [
                    'organization_id' => null,
                    'name' => $role->name,
                    'description' => $role->description,
                    'source' => RoleSource::Manifest->value,
                    'orphaned_at' => null,
                ],
            );

            $this->wireRolePermissions($model->id, $role, $permissionIds);
        }
    }

    /**
     * @param  Collection<array-key, mixed>  $permissionIds  permission key => id
     */
    private function wireRolePermissions(string $roleId, DeclaredRole $role, Collection $permissionIds): void
    {
        $desired = [];
        foreach ($role->permissions as $permissionKey) {
            $permissionId = $permissionIds->get($permissionKey);
            if (is_string($permissionId)) {
                $desired[$permissionId] = ['role_id' => $roleId, 'permission_id' => $permissionId];
            }
        }

        // Replace the role's grants with exactly the declared set.
        DB::table('role_permission')->where('role_id', $roleId)->delete();

        if ($desired !== []) {
            DB::table('role_permission')->insertOrIgnore(array_values($desired));
        }
    }

    /**
     * @param  list<string>  $declaredKeys
     * @return list<string> the keys flagged orphaned
     */
    private function flagOrphanedRoles(string $clientId, array $declaredKeys): array
    {
        return $this->flagOrphaned(
            Role::query()->where('client_id', $clientId)->whereNull('orphaned_at'),
            'key',
            $declaredKeys,
        );
    }

    /**
     * @param  list<string>  $declaredKeys
     * @return list<string>
     */
    private function flagOrphanedPermissions(string $clientId, array $declaredKeys): array
    {
        return $this->flagOrphaned(
            Permission::query()->where('client_id', $clientId)->whereNull('orphaned_at'),
            'name',
            $declaredKeys,
        );
    }

    /**
     * Mark every currently-declared row whose key is absent from the new manifest as
     * orphaned (kept, not deleted). Returns the affected keys.
     *
     * @param  Builder<covariant \Illuminate\Database\Eloquent\Model>  $query
     * @param  list<string>  $declaredKeys
     * @return list<string>
     */
    private function flagOrphaned($query, string $keyColumn, array $declaredKeys): array
    {
        $orphans = (clone $query)
            ->when($declaredKeys !== [], fn ($q) => $q->whereNotIn($keyColumn, $declaredKeys))
            ->get();

        $keys = [];
        foreach ($orphans as $orphan) {
            $value = $orphan->getAttribute($keyColumn);
            if (is_string($value)) {
                $keys[] = $value;
            }
        }

        if ($keys !== []) {
            (clone $query)->whereIn($keyColumn, $keys)->update(['orphaned_at' => now()]);
        }

        return $keys;
    }
}
