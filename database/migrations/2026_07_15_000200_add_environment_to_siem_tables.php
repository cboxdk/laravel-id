<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
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
        Schema::table('log_streams', function (Blueprint $table): void {
            $table->ulid('environment_id')->after('id')->index();
        });

        Schema::table('stream_deliveries', function (Blueprint $table): void {
            $table->ulid('environment_id')->after('id')->index();
        });
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
