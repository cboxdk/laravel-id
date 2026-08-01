<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Give the SAML replay ledger the key it should always have had.
 *
 * `consumed_assertions.assertion_id` carried a GLOBAL unique. An assertion ID is chosen
 * by the ISSUING identity provider and is only required to be unique within it — the
 * SAML 2.0 core spec asks for uniqueness "within the issuer", not across the world, and
 * short or sequential IDs are common in the wild (staging IdPs and several appliance
 * vendors emit them). So two customers' identity providers can legitimately mint the
 * same ID, and the global unique turned the second tenant's perfectly valid login into
 * "assertion replay detected".
 *
 * That is a cross-tenant denial of service on the sign-in path — and a targetable one:
 * anyone who can make tenant A consume a chosen ID can lock tenant B out of that ID.
 *
 * The correct replay key is (environment, connection, assertion id): single-use per
 * issuing IdP, which is exactly what the replay guard is defending. This is the same
 * correction already made one table over, for the same reason — see
 * 2026_07_25_003100_key_dpop_proofs_by_jkt_and_environment, whose `unique(jti)` rejected
 * an unrelated client's valid proof.
 *
 * Both new columns are NOT NULL with a `''` default rather than nullable, because SQL
 * treats NULLs as distinct in a unique index: a nullable column would make the replay
 * guard silently stop firing for any row that lacked one. Same reasoning as the DPoP
 * table's `jkt`.
 *
 * No backfill: every row here expires within the assertion's own validity window (ten
 * minutes at the outside), so by the time a deploy completes they are all dead. They
 * keep `''`, which pairs with their already-unique assertion id.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('consumed_assertions', function (Blueprint $table): void {
            $table->dropUnique(['assertion_id']);
        });

        Schema::table('consumed_assertions', function (Blueprint $table): void {
            $table->string('environment_id', 26)->default('')->after('id');
            $table->string('connection_id', 26)->default('')->after('environment_id');
            $table->unique(['environment_id', 'connection_id', 'assertion_id'], 'consumed_assertions_replay_key');
        });
    }

    public function down(): void
    {
        Schema::table('consumed_assertions', function (Blueprint $table): void {
            $table->dropUnique('consumed_assertions_replay_key');
            $table->dropColumn(['environment_id', 'connection_id']);
        });

        Schema::table('consumed_assertions', function (Blueprint $table): void {
            $table->unique(['assertion_id']);
        });
    }
};
