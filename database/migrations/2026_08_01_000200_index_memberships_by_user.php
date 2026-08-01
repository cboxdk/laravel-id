<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Give "which organizations does this subject belong to" an index to stand on.
 *
 * `memberships` was created with indexes on `environment_id` and `organization_id` and a
 * `unique(organization_id, user_id)`. `user_id` is the SECOND column of that unique, and
 * a composite index cannot serve a predicate on its second column alone — so a lookup by
 * `user_id` had nothing at all.
 *
 * That would be a footnote if the query were rare. It is the opposite: `forUser()` runs
 * `withoutScope` by design — a subject's own list of organizations is cross-tenant by
 * nature — so the SQL carries no environment filter either. The result is a full scan of
 * every membership belonging to every tenant on the platform, and it runs from the host's
 * authentication middleware on every request, including every Livewire round trip.
 *
 * So one customer's page load got slower as OTHER customers signed up. That is the part
 * worth naming: not a slow query, a shared-fate one.
 *
 * `(user_id, created_at, id)` rather than `user_id` alone, because `forUser()` orders by
 * exactly that pair — the index then answers the sort as well as the filter.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('memberships', function (Blueprint $table): void {
            $table->index(['user_id', 'created_at', 'id'], 'memberships_user_ordered_idx');
        });
    }

    public function down(): void
    {
        Schema::table('memberships', function (Blueprint $table): void {
            $table->dropIndex('memberships_user_ordered_idx');
        });
    }
};
