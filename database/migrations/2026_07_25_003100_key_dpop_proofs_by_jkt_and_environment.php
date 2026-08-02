<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Fix the DPoP replay table's key, and give it the environment column every other
 * credential-bearing table in the platform already has.
 *
 * Three problems, all in one table:
 *
 * 1. The replay guard was `unique('jti')` — GLOBAL. RFC 9449 §11.1 makes a proof
 *    single-use per KEY: `jti` is a nonce the client chooses, and two unrelated
 *    clients with unrelated keys can legitimately pick the same value. A global
 *    unique rejects the second one as a replay, which it is not. The correct
 *    replay key is `(jkt, jti)` — the proof's key thumbprint plus its nonce.
 *
 * 2. There was no `environment_id` AT ALL — the only table in the platform without
 *    one. Added nullable so a DPoP proof presented on the platform plane (which
 *    deliberately runs without an environment) still records, and so the column can
 *    be backfilled before any code reads it.
 *
 * 3. There was no index on `expires_at`, despite the identically-purposed
 *    `consumed_assertions.expires_at` having one since day one. `cbox-id:prune`
 *    sweeps on exactly that column, and this is the fastest-growing table in the
 *    system: one INSERT per DPoP-protected request, forever.
 *
 * `jkt` is NOT NULL with a `''` default rather than nullable, because SQL treats
 * NULLs as distinct in a unique index — a nullable `jkt` would make the replay guard
 * silently stop firing for any row that lacked one. The same reasoning already
 * governs `usage_counters.organization_id` and `audit_logs`' platform sentinel.
 *
 * No backfill is needed for pre-existing rows: every row in this table expires within
 * the proof freshness window (60 seconds), so by the time the deploy completes they
 * are all dead. They keep `jkt = ''`, which pairs with their already-unique `jti`.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('dpop_proofs', function (Blueprint $table): void {
            $table->string('environment_id', 26)->nullable()->after('id')->index();
            // 64, not the 255 default. An RFC 7638 thumbprint is a fixed 43-character
            // base64url string, and this column is half of a unique index on the
            // fastest-growing table in the system — a 255-char member would push the
            // (jkt, jti) key past MySQL 5.7's 767-byte prefix limit for no benefit.
            $table->string('jkt', 64)->default('')->after('environment_id');
        });

        // Add the replacement BEFORE dropping what it replaces. MySQL DDL is not
        // transactional, so a failure between two statements is a state, not a rollback
        // — and in this order the window between them holds two constraints instead of
        // none. The other order leaves proof-JTI replay unconstrained on a table whose
        // whole purpose is refusing replay, with the migration unrecorded so the deploy
        // that would fix it cannot run either.
        Schema::table('dpop_proofs', function (Blueprint $table): void {
            $table->unique(['jkt', 'jti'], 'dpop_proofs_jkt_jti_unique');
            $table->index('expires_at');
        });

        Schema::table('dpop_proofs', function (Blueprint $table): void {
            $table->dropUnique(['jti']);
        });
    }

    public function down(): void
    {
        Schema::table('dpop_proofs', function (Blueprint $table): void {
            $table->dropIndex(['expires_at']);
            $table->dropUnique('dpop_proofs_jkt_jti_unique');
            $table->unique('jti');
        });

        Schema::table('dpop_proofs', function (Blueprint $table): void {
            $table->dropColumn('jkt');
            $table->dropIndex(['environment_id']);
            $table->dropColumn('environment_id');
        });
    }
};
