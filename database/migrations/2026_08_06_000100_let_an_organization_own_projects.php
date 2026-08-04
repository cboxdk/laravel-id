<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Let an ORGANIZATION own IdP products directly.
 *
 * `accounts.organization_id` already says an account IS an organization in the
 * platform-root environment — the account row just carries the members and the
 * payment method on top. So a project that belongs to an account already belongs,
 * transitively, to that account's organization; this column makes the link DIRECT
 * so ownership can be read from the organization side without going through the
 * account plane at all.
 *
 * ADDITIVE ONLY. `account_id` stays NOT NULL and keeps its cascade: every existing
 * reader (`Account::projects()`, `Projects::forAccount()`, the provisioner) is
 * untouched, and a consumer that never looks at the new column sees no change.
 * Dropping the account requirement — making `account_id` nullable, as
 * `environments.account_id` already is, so an organization can own a project with
 * no account behind it at all — is the SUBTRACTIVE step, deliberately not this one.
 *
 * No foreign key, matching `accounts.organization_id` (unique, unconstrained) and
 * the organization tables themselves, which carry none: `organizations` is
 * environment-owned and the platform plane deliberately does not take referential
 * locks across the tenancy boundary. The unique index is the guard that matters
 * here, and it costs no lock on `organizations` when this runs live.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('projects', function (Blueprint $table): void {
            $table->string('organization_id', 26)->nullable()->after('account_id');

            // The same shape as the `(account_id, slug)` key it parallels: a project
            // handle is unique within its owner. Two organizations may each have a
            // "default"; one organization may not have two. Rows with a NULL
            // organization (an account provisioned before the unified-identity
            // cutover, so never homed) do not collide with each other on SQLite,
            // MySQL or PostgreSQL — all three treat NULLs as distinct in a unique
            // index. Its leftmost prefix is also the `organization_id` lookup index,
            // so no separate index is added.
            //
            // Widths match the existing key exactly (a 26-char ULID plus the shared
            // `slug` column), so it stays well inside MySQL's 3072-byte limit.
            $table->unique(['organization_id', 'slug']);
        });

        // Backfill every homed account's projects. Idempotent — `whereNull` means a
        // re-run after a partial failure, or after this migration is rolled back and
        // re-applied, touches only the rows still missing the link, and never
        // overwrites an organization a later write has already set.
        //
        // Cursored rather than loaded: a live platform-root has one account row per
        // customer, and this must not size its memory to the customer count.
        foreach (DB::table('accounts')->whereNotNull('organization_id')->orderBy('id')->cursor() as $account) {
            DB::table('projects')
                ->where('account_id', $account->id)
                ->whereNull('organization_id')
                ->update(['organization_id' => $account->organization_id]);
        }
    }

    public function down(): void
    {
        // Separate statements on purpose. SQLite rebuilds the table to drop a column
        // and re-validates every surviving index against the new definition, so an
        // index still naming the dropped column fails the drop outright — the same
        // trap `add_project_id_to_environments` documents.
        Schema::table('projects', function (Blueprint $table): void {
            $table->dropUnique(['organization_id', 'slug']);
        });

        Schema::table('projects', function (Blueprint $table): void {
            $table->dropColumn('organization_id');
        });
    }
};
