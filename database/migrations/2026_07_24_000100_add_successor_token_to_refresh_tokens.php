<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Idempotent rotation: when a refresh token is rotated we record its successor
     * (encrypted at rest) so that a re-presentation within the grace window returns
     * the SAME successor instead of minting a second, independent live token. Without
     * this, a concurrent/replayed refresh within the grace window produced two valid
     * sibling tokens — a stolen token could be laundered into its own live lineage
     * during the window. Additive + nullable, so it is safe to deploy ahead of the
     * code and backfills to NULL for existing rows.
     */
    public function up(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->text('successor_token')->nullable()->after('jkt');
        });
    }

    public function down(): void
    {
        Schema::table('oauth_refresh_tokens', function (Blueprint $table): void {
            $table->dropColumn('successor_token');
        });
    }
};
