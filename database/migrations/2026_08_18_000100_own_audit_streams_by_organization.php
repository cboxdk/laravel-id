<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Gives an audit stream an owning organization, so a tenant's SIEM receives that tenant's
 * events and not the environment's.
 *
 * A stream was environment-owned and nothing else: every entry recorded anywhere in the
 * environment was mirrored to every enabled stream in it. That was correct while only an
 * operator could configure one — and the console has since put log streaming on the
 * ORGANIZATION plane, on the fair argument that shipping an audit trail to a SIEM is a
 * compliance obligation the organization carries. The two together mean an administrator
 * of organization A registers an endpoint and receives organizations B and C's sign-ins,
 * role changes and member events. Not a leak they had to work for: it is the feature,
 * working as built, on a plane that was never in its design.
 *
 * NULLABLE, and null keeps meaning what it meant: the environment's own stream, receiving
 * everything, configurable only from the environment plane. Existing rows were created
 * under exactly that rule, so leaving them null preserves what every one of them was for
 * — a backfill would have to invent an owner none of them has.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasColumn('log_streams', 'organization_id')) {
            return;
        }

        Schema::table('log_streams', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->after('environment_id');
            // Delivery asks "this environment's streams, for this organization or for all
            // of it" on every recorded entry, which is the hottest read this table has.
            $table->index(['environment_id', 'organization_id'], 'log_streams_env_org_index');
        });
    }

    public function down(): void
    {
        if (! Schema::hasColumn('log_streams', 'organization_id')) {
            return;
        }

        Schema::table('log_streams', function (Blueprint $table): void {
            $table->dropIndex('log_streams_env_org_index');
            $table->dropColumn('organization_id');
        });
    }
};
