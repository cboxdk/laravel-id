<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The index the CORS preflight reads.
 *
 * `frontend_api_origins` had one index — `unique(frontend_api_key_id, origin)` — and
 * `origin` is its SECOND column, so a lookup that knows only the origin cannot use it. That
 * was fine while every query started from a key.
 *
 * The preflight does not have a key. A browser never sends a custom header on an OPTIONS
 * request, so the door answers it on the `Origin` alone — which means an unauthenticated
 * caller, from anywhere, forces a walk of every origin row in the environment on a request
 * that reaches no rate limiter. `Access-Control-Max-Age` bounds how often a real browser
 * asks; it bounds nothing else.
 *
 * The same defect was paid for once already on `memberships.user_id`
 * ({@see 2026_08_01_000200_index_memberships_by_user}) — a second column of a composite
 * index doing duty as a first — and this one sits on the only endpoint in the product that
 * requires no credential at all.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('frontend_api_origins', function (Blueprint $table): void {
            // Not unique: two keys in one environment may legitimately name the same
            // origin — a marketing site and an app that share a domain — and the pair
            // above is what keeps a single key from naming one twice.
            $table->index('origin', 'frontend_api_origins_origin_idx');
        });
    }

    public function down(): void
    {
        Schema::table('frontend_api_origins', function (Blueprint $table): void {
            $table->dropIndex('frontend_api_origins_origin_idx');
        });
    }
};
