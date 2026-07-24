<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Environment-scope the permission catalog. An APP-DECLARED permission (non-null
 * `client_id`) belongs to exactly the environment of its declaring client, so an
 * environment admin can no longer see — or bind into a role — another environment's
 * declared `feature:action` keys. A MANUAL permission (null `client_id`) keeps
 * `environment_id` null: it is platform-global and shared across every environment
 * by design.
 *
 * The backfill derives each declared permission's environment from its client via a
 * correlated subquery (portable across sqlite/mysql/pgsql). Manual rows are left null.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('permissions', function (Blueprint $table): void {
            $table->ulid('environment_id')->nullable()->after('client_id')->index();
        });

        // Backfill declared permissions from their declaring client's environment.
        // Correlated UPDATE subquery — works identically on sqlite, mysql and pgsql.
        DB::statement(<<<'SQL'
            UPDATE permissions
            SET environment_id = (
                SELECT oauth_clients.environment_id
                FROM oauth_clients
                WHERE oauth_clients.client_id = permissions.client_id
            )
            WHERE client_id IS NOT NULL
        SQL);
    }

    public function down(): void
    {
        Schema::table('permissions', function (Blueprint $table): void {
            $table->dropIndex(['environment_id']);
            $table->dropColumn('environment_id');
        });
    }
};
