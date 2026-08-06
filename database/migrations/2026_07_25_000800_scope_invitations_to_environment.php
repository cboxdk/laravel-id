<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Environment-scope the invitation table.
 *
 * `invitations` was the ONLY credential-bearing table in the platform without an
 * `environment_id` — every sibling (magic links, password-reset and email-verification
 * tokens, sessions, users, memberships, role assignments) is environment-owned. The
 * omission made the accept route a cross-environment primitive: `byToken()` matched on
 * `token_hash` alone, so a token minted in one environment was redeemable on ANY host,
 * and the resulting user, membership and session rows were stamped from whatever
 * environment the redeeming host resolved to.
 *
 * The backfill derives each invitation's environment from its organization via a
 * correlated subquery — portable across sqlite/mysql/pgsql, same shape as
 * `2026_07_24_000200_scope_permissions_to_environment`.
 *
 * ADDITIVE and nullable: the column is added and populated before any code reads it,
 * so old pods keep serving during a rolling deploy. Rows whose organization no longer
 * exists stay null and are unreachable through the env-scoped model — which is the
 * correct outcome for an invitation into a deleted org.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('invitations', function (Blueprint $table): void {
            $table->string('environment_id', 26)->nullable()->after('id')->index();
        });

        DB::statement(<<<'SQL'
            UPDATE invitations
            SET environment_id = (
                SELECT organizations.environment_id
                FROM organizations
                WHERE organizations.id = invitations.organization_id
            )
        SQL);
    }

    public function down(): void
    {
        Schema::table('invitations', function (Blueprint $table): void {
            $table->dropIndex(['environment_id']);
            $table->dropColumn('environment_id');
        });
    }
};
