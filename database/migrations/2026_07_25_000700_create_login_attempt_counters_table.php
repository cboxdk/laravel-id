<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Failed password attempts per subject, and the lockout they trigger.
 *
 * A table rather than the cache: a lockout is a security decision that must survive a
 * cache eviction and be identical on every pod. Losing it because a Redis node cycled
 * would silently reset an attacker's budget.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('login_attempt_counters', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->ulid('environment_id')->index();
            $table->ulid('user_id');

            $table->unsignedInteger('failures')->default(0);

            // When the current counting window began. Failures older than the window are
            // not evidence of an attack in progress, so the count starts again.
            $table->timestamp('window_started_at')->nullable();

            // Set once the threshold is crossed; null when not locked.
            $table->timestamp('locked_until')->nullable();

            $table->timestamps();

            $table->unique(['environment_id', 'user_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('login_attempt_counters');
    }
};
