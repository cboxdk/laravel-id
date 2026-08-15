<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Give a manual permission an OWNER.
 *
 * A manual permission (null `client_id`) carried an `environment_id` and nothing else, so
 * the catalog had exactly two tiers: platform-global and environment-wide. The console
 * offers the authoring form on BOTH planes — an organization admin can reach it — and
 * every row they wrote landed in the environment-wide tier, shared with every other
 * tenant in that environment. One tenant could therefore rename or DELETE a key another
 * tenant's roles were built from, and deleting cascades the `role_permission` rows for
 * every role in the environment.
 *
 * `organization_id` names the third tier: authored by a tenant, usable by that tenant,
 * invisible to its peers. Null keeps its existing meaning — shared with the environment,
 * which is what the environment-plane form still writes.
 *
 * NULLABLE AND NOT BACKFILLED, deliberately. Every row that exists today was authored on
 * a plane where "shared with the environment" was the only outcome available, and roles
 * across the environment may already bind them; stamping them with a guessed owner would
 * revoke permissions from live roles. Existing rows stay shared; the fence applies from
 * here forward.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('permissions', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->after('environment_id')->index();
        });
    }

    public function down(): void
    {
        Schema::table('permissions', function (Blueprint $table): void {
            $table->dropIndex(['organization_id']);
            $table->dropColumn('organization_id');
        });
    }
};
