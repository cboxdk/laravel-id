<?php

declare(strict_types=1);

use Cbox\Id\Platform\DatabaseAccountMembers;
use Cbox\Id\Platform\Enums\AccountRole;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Make each account membership say what the member actually holds.
 *
 * WHY THESE ROWS ARE WRONG. {@see DatabaseAccountMembers::attachSubject()} wrote a neutral
 * `member` for everybody, and `2026_08_05_000200` copied that choice when it placed the
 * people of every previously-unhomed account. Both were right at the time: `AccountRole`
 * on the member row was the single authority for account capabilities, and mirroring it
 * onto the membership would have been a second truth to drift.
 *
 * The console asks the MEMBERSHIP now. So a neutral role is no longer a deliberate
 * abstention — it is the wrong answer to the only question being asked, and it makes an
 * account's own owner a plain member of the organization they own.
 *
 * BILLING BECOMES VIEWER, which is the one case that loses something. `MembershipRole` has
 * no billing case and should not gain one: `canWrite()` is "not a Viewer", so a new role
 * would arrive holding write access to every organization on every tenant, and correcting
 * that changes what `canWrite()` means for everybody. Viewer keeps the reachable half —
 * reading the plan — and drops `canManageBilling()`, which no page and no route asks for.
 * {@see AccountRole::asMembershipRole()} is where that decision is written down.
 *
 * ONLY THE ACCOUNTS' OWN ORGANIZATIONS ARE TOUCHED. The update is keyed on
 * `(accounts.organization_id, account_members.subject_id)`, so an ordinary tenant
 * membership — somebody in a customer's organization who has no account member row at all
 * — is not in the join and cannot be re-roled by this.
 */
return new class extends Migration
{
    public function up(): void
    {
        $members = DB::table('account_members')
            ->join('accounts', 'accounts.id', '=', 'account_members.account_id')
            ->whereNotNull('account_members.subject_id')
            ->where('account_members.subject_id', '!=', '')
            ->whereNotNull('accounts.organization_id')
            ->get([
                'account_members.subject_id as subject_id',
                'account_members.role as role',
                'accounts.organization_id as organization_id',
            ]);

        foreach ($members as $member) {
            $role = is_string($member->role) ? AccountRole::tryFrom($member->role) : null;
            $subjectId = $member->subject_id;
            $organizationId = $member->organization_id;

            // A role the enum does not know is left alone rather than defaulted. Guessing
            // would either widen somebody's access or narrow it, and both are worse than a
            // row an operator can still see and correct.
            if ($role === null || ! is_string($subjectId) || ! is_string($organizationId)) {
                continue;
            }

            DB::table('memberships')
                ->where('organization_id', $organizationId)
                ->where('user_id', $subjectId)
                ->update(['role' => $role->asMembershipRole()->value, 'updated_at' => now()]);
        }
    }

    /**
     * NOT REVERSED. Putting every one of these back to `member` would re-create the defect
     * on a deployment that has since had the console read them — and unlike the forward
     * direction there is no source to derive the previous value from, because the previous
     * value was the same for everybody regardless of what they held.
     */
    public function down(): void {}
};
