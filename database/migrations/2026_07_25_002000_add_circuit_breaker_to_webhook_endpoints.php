<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Health columns backing the per-endpoint webhook circuit breaker.
 *
 * Deliberately SEPARATE from `status`: that column carries operator INTENT
 * (`paused` is set by hand and cleared by hand), while these carry transient
 * HEALTH that heals itself after the cooldown. Folding a trip into `status`
 * would also make DatabaseWebhookRegistry::matching() — which filters on
 * `status = active` — stop writing delivery rows for a tripped endpoint, so
 * events would be silently DROPPED instead of merely delayed.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('webhook_endpoints', function (Blueprint $table): void {
            $table->unsignedInteger('consecutive_failures')->default(0);
            $table->timestamp('circuit_opened_at')->nullable()->index();
            $table->timestamp('last_success_at')->nullable();
            $table->text('last_error')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('webhook_endpoints', function (Blueprint $table): void {
            $table->dropColumn(['consecutive_failures', 'circuit_opened_at', 'last_success_at', 'last_error']);
        });
    }
};
