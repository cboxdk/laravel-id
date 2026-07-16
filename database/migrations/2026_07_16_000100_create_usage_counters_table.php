<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Per-day usage counters. organization_id is '' (not NULL) for a system-scoped
        // count, so the unique index serialises upserts on every DB (NULLs are treated
        // as distinct by SQLite/Postgres and would let duplicate rows accumulate).
        Schema::create('usage_counters', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->string('organization_id')->default('')->index();
            $table->string('metric');
            $table->string('period', 10); // Y-m-d
            $table->unsignedBigInteger('count')->default(0);
            $table->timestamps();

            // env-first so the hard scope's WHERE environment_id hits the index.
            $table->unique(['environment_id', 'organization_id', 'metric', 'period'], 'usage_counters_key');
            $table->index(['environment_id', 'metric', 'period']);
        });

        // Dedup marker so at-least-once event delivery meters each event exactly once.
        Schema::create('usage_metered_events', function (Blueprint $table): void {
            $table->string('event_id', 40)->primary();
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('usage_metered_events');
        Schema::dropIfExists('usage_counters');
    }
};
