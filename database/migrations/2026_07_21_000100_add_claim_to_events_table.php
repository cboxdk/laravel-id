<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('events', function (Blueprint $table): void {
            // Claim marker for the relay. Two relays (a scheduler tick overlapping a
            // long pass, or two app instances) previously selected the same pending
            // rows and dispatched every event twice — every webhook delivered twice,
            // every usage counter incremented twice.
            //
            // A separate column rather than stamping dispatched_at early: claiming and
            // delivering are different facts. A row claimed but never dispatched is a
            // relay that died mid-pass, and can be safely reclaimed once the claim goes
            // stale — whereas an early dispatched_at would silently lose the event.
            $table->timestamp('claimed_at')->nullable()->after('dispatched_at');

            // The relay's own query: pending rows, oldest first. Without this it is a
            // scan of an append-only table that only grows.
            $table->index(['dispatched_at', 'claimed_at', 'occurred_at'], 'events_relay_idx');
        });
    }

    public function down(): void
    {
        Schema::table('events', function (Blueprint $table): void {
            $table->dropIndex('events_relay_idx');
            $table->dropColumn('claimed_at');
        });
    }
};
