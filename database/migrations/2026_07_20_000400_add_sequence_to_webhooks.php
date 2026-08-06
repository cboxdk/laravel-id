<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A per-endpoint monotonic delivery sequence. Each endpoint carries a `last_sequence`
 * counter; every delivery to it is stamped with the next value and the envelope
 * carries it as `sequence`. A receiver can then order events and detect a gap (a
 * missed delivery) — which an out-of-order, at-least-once webhook stream otherwise
 * hides. The sequence is per-endpoint, so each subscriber sees a clean 1, 2, 3, … .
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('webhook_endpoints', function (Blueprint $table): void {
            $table->unsignedBigInteger('last_sequence')->default(0)->after('event_types');
        });

        Schema::table('webhook_deliveries', function (Blueprint $table): void {
            $table->unsignedBigInteger('sequence')->nullable()->after('event_type');
        });
    }

    public function down(): void
    {
        Schema::table('webhook_endpoints', function (Blueprint $table): void {
            $table->dropColumn('last_sequence');
        });

        Schema::table('webhook_deliveries', function (Blueprint $table): void {
            $table->dropColumn('sequence');
        });
    }
};
