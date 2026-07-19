<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * Nest environments under a project. `project_id` is NULLABLE for the same reason
 * `account_id` is: a null project is the sentinel for a platform-owned environment —
 * the single-tenant / self-hosted deployment's one forced IdP, which has no account
 * and no project and lives on a single domain. The Project layer is a SaaS-only
 * (Tier-2, multi-tenant) concept; single-tenant never populates it.
 *
 * Backfill: every EXISTING account gets one "Default" project inheriting the account's
 * environment_limit, and that account's environments are repointed to it — so no
 * multi-tenant account loses access mid-flight. Platform envs (null account_id) keep
 * a null project_id.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->foreignUlid('project_id')->nullable()->after('account_id')
                ->constrained('projects')->restrictOnDelete();
            $table->index('project_id');
        });

        // Backfill a "Default" project per account, then repoint its environments.
        // Idempotent: an account that already has a project (e.g. a re-run after a
        // partial failure, or a rollback of only this migration) is skipped, so the
        // unique (account_id, slug) constraint is never violated.
        foreach (DB::table('accounts')->get() as $account) {
            if (DB::table('projects')->where('account_id', $account->id)->exists()) {
                continue;
            }

            $projectId = (string) Str::ulid();
            DB::table('projects')->insert([
                'id' => $projectId,
                'account_id' => $account->id,
                'name' => 'Default',
                'slug' => 'default',
                'status' => 'active',
                'environment_limit' => $account->environment_limit ?? 2,
                'settings' => '{}',
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            DB::table('environments')
                ->where('account_id', $account->id)
                ->whereNull('project_id')
                ->update(['project_id' => $projectId]);
        }
    }

    public function down(): void
    {
        Schema::table('environments', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('project_id');
        });
    }
};
