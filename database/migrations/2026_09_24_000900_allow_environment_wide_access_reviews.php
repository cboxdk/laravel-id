<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * An access review of the grants that belong to NO organization.
 *
 * Environment-wide role grants (`environment_role_assignments`) are the largest grants in
 * the system — a staff role held across every customer — and they were the only grants no
 * access review could enumerate: a campaign was always one organization's, and its
 * snapshot read that organization's own rows. So the one kind of access most worth
 * certifying was the one kind never certified.
 *
 * A campaign (and its items) with a NULL organization is the environment's own review.
 * Nullable rather than a second pair of tables for the same reason connections went this
 * way: neither table has a unique index over the organization, so NULL cannot duplicate
 * a row, and "this review belongs to the environment" is the same kind of statement as
 * "it belongs to Acme". Every existing row keeps its organization.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('governance_campaigns', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->change();
        });

        Schema::table('governance_certification_items', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->change();
        });
    }

    public function down(): void
    {
        // An environment review cannot be represented once the column is NOT NULL again,
        // so rolling back removes those reviews (their decisions stay on the audit trail,
        // which is where the evidence lives). Items first, then their campaigns.
        DB::table('governance_certification_items')->whereNull('organization_id')->delete();
        DB::table('governance_campaigns')->whereNull('organization_id')->delete();

        Schema::table('governance_certification_items', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable(false)->change();
        });

        Schema::table('governance_campaigns', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable(false)->change();
        });
    }
};
