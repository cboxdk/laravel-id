<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Bound the outbox relay's retries.
 *
 * The relay isolates a throwing listener and releases the claim so the event retries on
 * the next pass — correct for a transient failure, unbounded for a permanent one. Nothing
 * counted attempts, so a row that could never succeed (a listener throwing on data that
 * will never change) was re-delivered on EVERY pass, forever: it could not be pruned
 * (that needs `dispatched_at`), it counted as backlog permanently, and because listeners
 * run in registration order, every listener after the throwing one — webhooks,
 * provisioning, usage metering, audit streaming — was skipped for that event on every
 * single pass.
 *
 * `attempts` counts the failures; `dead_lettered_at` is the terminal marker for a row
 * that exhausted them. It is deliberately NOT `dispatched_at`: a dead-lettered event was
 * never delivered, and an operator looking for lost work must be able to tell the two
 * apart.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('events', function (Blueprint $table): void {
            $table->unsignedInteger('attempts')->default(0)->after('claim_token');
            $table->timestamp('dead_lettered_at')->nullable()->after('attempts')->index();
        });
    }

    public function down(): void
    {
        Schema::table('events', function (Blueprint $table): void {
            $table->dropIndex(['dead_lettered_at']);
            $table->dropColumn(['attempts', 'dead_lettered_at']);
        });
    }
};
