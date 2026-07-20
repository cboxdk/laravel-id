<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A per-endpoint delivery sequence must be unique so a receiver's gap-detection is
 * trustworthy: the dispatcher allocates it under a row lock, and this constraint is
 * the backstop that turns any residual race into a hard error rather than a silent
 * duplicate. Nullable `sequence` rows (there should be none post-allocation) are
 * exempt — a partial-style unique on (endpoint_id, sequence) still allows many nulls.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('webhook_deliveries', function (Blueprint $table): void {
            $table->unique(['endpoint_id', 'sequence'], 'webhook_deliveries_endpoint_sequence_unique');
        });
    }

    public function down(): void
    {
        Schema::table('webhook_deliveries', function (Blueprint $table): void {
            $table->dropUnique('webhook_deliveries_endpoint_sequence_unique');
        });
    }
};
