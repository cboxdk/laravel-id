<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The environment-wide audit browse runs `WHERE environment_id = ? ORDER BY sequence
 * DESC LIMIT n` with no organization filter. Neither existing composite serves it —
 * `(environment_id, scope, sequence)` and `(environment_id, organization_id, sequence)`
 * both put an unconstrained column between the equality and the sort — so the optimizer
 * filters on the single `environment_id` index and filesorts by `sequence`. Add the
 * ordered prefix so the browse is index-only. Additive; the high-volume export cursor
 * (always organization-filtered) is unaffected and keeps its own composite.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('audit_logs', function (Blueprint $table): void {
            $table->index(['environment_id', 'sequence']);
        });
    }

    public function down(): void
    {
        Schema::table('audit_logs', function (Blueprint $table): void {
            $table->dropIndex(['environment_id', 'sequence']);
        });
    }
};
