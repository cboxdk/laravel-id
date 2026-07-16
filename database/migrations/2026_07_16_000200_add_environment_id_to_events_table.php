<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Records the origin environment on each outbox event, so downstream projections
 * (analytics, per-environment metering) can attribute a delivered event to its
 * environment. Nullable — system events have none — and deliberately NOT a
 * tenant-scoped relation: the relay flushes pending events across environments.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('events', function (Blueprint $table): void {
            $table->ulid('environment_id')->nullable()->after('organization_id')->index();
        });
    }

    public function down(): void
    {
        Schema::table('events', function (Blueprint $table): void {
            $table->dropIndex(['environment_id']);
            $table->dropColumn('environment_id');
        });
    }
};
