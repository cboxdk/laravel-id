<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Move per-member ENVIRONMENT GRANTS onto the membership.
 *
 * A member of an account may be restricted to a subset of the environments that account
 * owns, instead of all of them. Today that lives on the account plane: a boolean
 * `account_members.all_environments` and an `account_member_environments` pivot. Three
 * authorization gates read it — whether a member may administer the host environment
 * (`EnvironmentAdminAuth`, `EnvironmentAdminController`) and whether a hand-off token may
 * be minted for one (`EnvironmentHandoffController`) — plus the console rail and the
 * environment-keys page.
 *
 * THIS IS WHY THE ACCOUNT PLANE CANNOT SIMPLY BE DROPPED. The tables were noted as
 * orphaned — no writer, no rows, no coverage — and that was wrong: `setEnvironmentAccess()`
 * is called from the console's own members page and covered by two test files. Dropping
 * `account_member_environments` without this migration would not remove a dead feature; it
 * would remove the basis of three live gates, and every one of them fails OPEN in the
 * direction that matters, because "no grants found" and "all environments" are told apart
 * by a boolean that would go with the table.
 *
 * SO THE GRANT MOVES BEFORE ANYTHING IS REMOVED, and this migration adds only. The account
 * plane's columns stay exactly where they are and keep working; nothing is dropped here,
 * and the readers are re-pointed in a separate change that can be reverted on its own.
 *
 * WHY THE MEMBERSHIP AND NOT THE SUBJECT. A grant is not a fact about a person — the same
 * subject may hold memberships in several organizations, and a restriction granted by one
 * organization must not follow them into another. `memberships` already has the
 * `(organization_id, user_id)` unique key that makes "this person, in this organization"
 * a single row, which is exactly the thing being restricted.
 *
 * THE PIVOT CROSSES ENVIRONMENTS ON PURPOSE, as its predecessor did. A membership in an
 * account's organization lives in the platform root; the environments it grants access to
 * are the tenant environments that organization owns, and they live in themselves. There
 * is no environment scope on the join table because `membership_id` already carries one —
 * a scope here would be a second, weaker copy of the boundary the membership already draws.
 *
 * `all_environments` DEFAULTS TRUE, matching what an invitation has always written. The
 * default has to be the permissive one: false would mean "restricted to the empty set", so
 * a deployment that ran this migration and had not yet been re-pointed would lock every
 * member out of every environment on the next request. The restriction is a thing an
 * administrator opts into, and it is stored as such.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('memberships', 'all_environments')) {
            Schema::table('memberships', function (Blueprint $table): void {
                $table->boolean('all_environments')->default(true)->after('status');
            });
        }

        if (! Schema::hasTable('membership_environments')) {
            Schema::create('membership_environments', function (Blueprint $table): void {
                $table->string('membership_id', 26);
                $table->string('environment_id', 26);

                // The primary key IS the pair: a grant either exists or it does not, and a
                // surrogate id would let the same grant be written twice with nothing
                // objecting. Its leftmost prefix is also the `membership_id` lookup, which
                // is the only direction anything reads, so no separate index is added.
                //
                // 52 bytes of key. Well inside MySQL's 3072-byte limit even on the
                // 4-bytes-per-character utf8mb4 worst case (208), which is the arithmetic
                // `2026_07_26_000100` had to go back and do for other tables.
                $table->primary(['membership_id', 'environment_id']);

                $table->foreign('membership_id')->references('id')->on('memberships')->cascadeOnDelete();

                // NO foreign key to `environments`, and that asymmetry is deliberate. A
                // membership and its grants are one object and go together; an environment
                // is on the other side of the tenancy boundary, where the platform plane
                // does not take referential locks — the same reasoning
                // `2026_08_06_000100` gives for `projects.organization_id`. A grant naming
                // an environment that has since been deleted reads as no access, which is
                // the safe direction.
            });
        }

        // Carry every existing restriction over. Only members that HAVE one are copied:
        // `all_environments = true` is already the new column's default, so a member with
        // no restriction needs no row written and no update issued.
        //
        // Keyed through `(accounts.organization_id, account_members.subject_id)` — the
        // same join `2026_08_06_000200` used to give each membership its role — so a
        // membership belonging to an ordinary tenant user, with no account member behind
        // it, is not in the join and cannot be touched by this.
        $restricted = DB::table('account_members')
            ->join('accounts', 'accounts.id', '=', 'account_members.account_id')
            ->join('memberships', function ($join): void {
                $join->on('memberships.organization_id', '=', 'accounts.organization_id')
                    ->on('memberships.user_id', '=', 'account_members.subject_id');
            })
            ->where('account_members.all_environments', false)
            ->get([
                'account_members.id as account_member_id',
                'memberships.id as membership_id',
            ]);

        foreach ($restricted as $row) {
            $membershipId = $row->membership_id;
            $accountMemberId = $row->account_member_id;

            if (! is_string($membershipId) || ! is_string($accountMemberId)) {
                continue;
            }

            DB::table('memberships')->where('id', $membershipId)->update([
                'all_environments' => false,
                'updated_at' => now(),
            ]);

            $grants = DB::table('account_member_environments')
                ->where('account_member_id', $accountMemberId)
                ->pluck('environment_id');

            foreach ($grants as $environmentId) {
                if (! is_string($environmentId) || $environmentId === '') {
                    continue;
                }

                // Idempotent: a re-run after a partial failure must not collide with the
                // rows it already wrote. `insertOrIgnore` rather than a read-then-insert,
                // which two concurrent runs would both pass.
                DB::table('membership_environments')->insertOrIgnore([
                    'membership_id' => $membershipId,
                    'environment_id' => $environmentId,
                ]);
            }
        }
    }

    /**
     * Reversible, and safely so — the account plane still holds the same restrictions,
     * because nothing above removed them. This drops a copy, not the original.
     */
    public function down(): void
    {
        Schema::dropIfExists('membership_environments');

        if (Schema::hasColumn('memberships', 'all_environments')) {
            Schema::table('memberships', function (Blueprint $table): void {
                $table->dropColumn('all_environments');
            });
        }
    }
};
