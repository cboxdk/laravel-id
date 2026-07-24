<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Environment-scope the manual permission catalog.
 *
 * A MANUAL permission (null `client_id`) used to be authored into the platform-global
 * (null `environment_id`) namespace, which made it visible — and destructively deletable,
 * cascading `role_permission` — from every environment's console. Manual permissions are
 * now stamped with their authoring environment so they belong to exactly one tenant.
 *
 * This backfills the environment for each pre-existing manual permission by inspecting
 * the roles that reference it: when every referencing role lives in ONE environment, that
 * is unambiguously the owner. Rows referenced by roles across multiple environments (the
 * cross-tenant coupling this remediates) or by none are left null for an operator to
 * resolve deliberately — guessing would strip a permission from another tenant's roles.
 *
 * Additive and data-only (the `environment_id` column already exists); no schema change.
 */
return new class extends Migration
{
    public function up(): void
    {
        $manualPermissionIds = DB::table('permissions')
            ->whereNull('client_id')
            ->whereNull('environment_id')
            ->pluck('id');

        foreach ($manualPermissionIds as $permissionId) {
            $environments = DB::table('role_permission')
                ->join('roles', 'roles.id', '=', 'role_permission.role_id')
                ->where('role_permission.permission_id', $permissionId)
                ->distinct()
                ->pluck('roles.environment_id')
                ->filter()
                ->values();

            if ($environments->count() === 1) {
                DB::table('permissions')
                    ->where('id', $permissionId)
                    ->update(['environment_id' => $environments->first()]);
            }
        }
    }

    public function down(): void
    {
        // Irreversible data backfill: we cannot distinguish an environment_id this
        // migration set from one already present, so reverting would risk nulling
        // legitimately-scoped rows. Intentionally a no-op.
    }
};
