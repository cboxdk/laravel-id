<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A pull directory's sync becomes something an administrator can see and pace.
 *
 * - `sync_interval_minutes`: how often THIS directory is pulled. Null is the configured
 *   default (`cbox-id.directory.default_interval_minutes`, hourly), which is what every
 *   directory written before this column got — so existing Google Workspace and Entra
 *   directories keep their pace.
 * - `last_sync_started_at`: what "due" is measured from, and how a run that never finished
 *   is told apart from one that never started.
 * - `last_sync_status` / `last_sync_stats`: running, succeeded, partial or failed, with the
 *   counts and the per-record failures of the last run (no personal data — see SyncFailure).
 * - `sync_cursor` / `last_full_sync_at`: for an HR system that can answer "changed since",
 *   the instant the last run started, and when the last FULL pull ran — only a full pull
 *   may deprovision the people it did not see, so incremental runs are bounded by one.
 *
 * All nullable and additive; nothing existing is rewritten.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('directories', function (Blueprint $table): void {
            $table->unsignedInteger('sync_interval_minutes')->nullable();
            $table->timestamp('last_sync_started_at')->nullable();
            $table->string('last_sync_status', 20)->nullable();
            $table->text('last_sync_stats')->nullable();
            $table->string('sync_cursor', 64)->nullable();
            $table->timestamp('last_full_sync_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('directories', function (Blueprint $table): void {
            $table->dropColumn([
                'sync_interval_minutes',
                'last_sync_started_at',
                'last_sync_status',
                'last_sync_stats',
                'sync_cursor',
                'last_full_sync_at',
            ]);
        });
    }
};
