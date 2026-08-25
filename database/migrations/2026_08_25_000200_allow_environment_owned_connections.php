<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * A federated sign-in that belongs to the ENVIRONMENT rather than to one tenant.
 *
 * `connections.organization_id` was NOT NULL, which made single sign-on — the flagship
 * capability of an identity provider — unavailable to any environment that does not use
 * organizations. An internal admin tool behind Okta is an ordinary thing to want, and the
 * only way to have it was to invent a tenancy that the product has no other use for, and
 * whose memberships then leak meaning into everything keyed on membership.
 *
 * NULLABLE HERE, unlike the environment-wide ROLE grant which got its own table. The
 * reasoning that split those two does not apply: `connections` has no unique index over
 * the organization, so NULL cannot silently duplicate a row, and "this connection belongs
 * to the environment" is the same KIND of statement as "it belongs to Acme" — one
 * connection, one owner, read the same way. A separate table would be two shapes for one
 * fact.
 *
 * Every existing row keeps its organization, and every existing read still names one.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('connections', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('connections', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable(false)->change();
        });
    }
};
