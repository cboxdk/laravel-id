<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Adds the hard environment boundary to cboxdk/laravel-siem's outbox tables.
 *
 * laravel-siem's own migration (2026_07_15_000100_create_siem_tables) creates
 * `log_streams` and `stream_deliveries` as tenancy-agnostic tables; this alter
 * runs AFTER it (later filename) and adds the indexed `environment_id` column that
 * the env-owned AuditStream / AuditStreamDelivery subclasses scope on. Existing
 * rows (there are none in a fresh install) would need backfilling — this package
 * ships the column as part of the same v0.9.0 release that introduces streaming,
 * so no backfill is required.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Nullable first, then backfilled, then tightened.
        //
        // Adding a NOT NULL column with no default to a table that already holds rows is
        // a PostgreSQL 23502 — and these tables come from a separate package, so "there
        // are no rows yet" is an assumption about someone else's install, not a fact
        // about ours. MySQL hides it by silently backfilling '', which is how it passed
        // here: green on the engine that guesses, broken on the one that refuses.
        //
        // Split across three statements rather than two blocks for the same reason the
        // constraint swaps were reordered: MySQL DDL is not transactional, so each step
        // has to leave the schema in a state the next run can still act on.
        foreach (['log_streams', 'stream_deliveries'] as $table) {
            Schema::table($table, function (Blueprint $blueprint): void {
                $blueprint->string('environment_id', 26)->nullable()->after('id')->index();
            });

            // Existing rows predate multi-environment support. Empty string rather than
            // a lookup: this migration must not depend on application state that may not
            // exist yet, and the column is only meaningful once an operator assigns it.
            DB::table($table)->whereNull('environment_id')->update(['environment_id' => '']);

            // Tightened WITHOUT a default. A default here is not merely unnecessary — a
            // later migration converts every identifier column from char to varchar and
            // deliberately refuses any column carrying one, rather than dropping it
            // silently. Adding one broke that conversion on both server engines while
            // sqlite stayed green, which is the same asymmetry this whole batch is about.
            Schema::table($table, function (Blueprint $blueprint): void {
                $blueprint->string('environment_id', 26)->nullable(false)->change();
            });
        }
    }

    public function down(): void
    {
        Schema::table('stream_deliveries', function (Blueprint $table): void {
            $table->dropIndex(['environment_id']);
            $table->dropColumn('environment_id');
        });

        Schema::table('log_streams', function (Blueprint $table): void {
            $table->dropIndex(['environment_id']);
            $table->dropColumn('environment_id');
        });
    }
};
