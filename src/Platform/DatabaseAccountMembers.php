<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Enums\AccountMemberStatus;
use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\Models\AccountMember;
use Closure;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Eloquent-backed account members. Like {@see DatabasePlatformOperators}, no
 * environment scope is applied — members authenticate at the platform root,
 * above every environment — and the miss path is constant-cost so a missing or
 * suspended member is indistinguishable by timing from an active one.
 *
 * THE CREDENTIAL LIVES ON THE SUBJECT. An account member is paired with an ordinary
 * subject in the platform-root environment ({@see PlatformRoot}), and that subject is
 * the credential of record: {@see verifyPassword()} asks it, {@see resetPassword()} and
 * {@see activate()} write to it. The member row remains the account-side aggregate —
 * which account, which {@see AccountRole}, which environments — but it is no longer a
 * second place a password can be checked. That is the whole point of the unification:
 * the identity stack (SSO, passkeys, MFA, the password policy, administrative password
 * assignment) exists once, and account members inherit all of it.
 * See docs/core-concepts/unified-account-identity.md.
 */
class DatabaseAccountMembers implements AccountMembers
{
    public function __construct(
        private readonly Hasher $hasher,
        private readonly Subjects $subjects,
        private readonly Memberships $memberships,
        private readonly PlatformRoot $platformRoot,
    ) {}

    public function find(string $id): ?AccountMember
    {
        return AccountMember::query()->whereKey($id)->first();
    }

    public function findByEmail(string $email): ?AccountMember
    {
        return AccountMember::query()->where('email', $email)->first();
    }

    public function findBySubject(string $subjectId): ?AccountMember
    {
        if ($subjectId === '') {
            return null;
        }

        return AccountMember::query()->where('subject_id', $subjectId)->first();
    }

    public function create(string $accountId, string $email, string $password, ?string $name = null): AccountMember
    {
        $member = AccountMember::query()->create([
            'account_id' => $accountId,
            'email' => $email,
            'name' => $name,
            // The account's first member owns it outright.
            'role' => AccountRole::Owner,
            'all_environments' => true,
            // The model's `hashed` cast hashes with the configured driver. Retained
            // only as the bootstrap credential (see verifyPassword) — once the member
            // has a subject, this column is never consulted.
            'password' => $password,
            'status' => AccountMemberStatus::Active,
        ]);

        $this->attachSubject($member, $password, active: true);

        return $member;
    }

    public function invite(string $accountId, string $email, AccountRole $role, ?string $name = null): AccountMember
    {
        $member = AccountMember::query()->create([
            'account_id' => $accountId,
            'email' => $email,
            'name' => $name,
            'role' => $role,
            // New members see every environment until an admin scopes them down.
            'all_environments' => true,
            // A random, unknown password so no usable credential exists before the
            // invitee sets their own. Immaterial anyway: 'invited' status blocks
            // authentication until activate() flips it to 'active'.
            'password' => Str::random(64),
            'status' => AccountMemberStatus::Invited,
        ]);

        // The subject is minted deactivated: an invitation is not yet an identity, and
        // a subject that could authenticate before the invite is accepted would be a
        // way into the platform root that bypasses the acceptance flow entirely.
        $this->attachSubject($member, Str::random(64), active: false);

        return $member;
    }

    /**
     * Pair a freshly-created member with their subject in the platform-root environment
     * and place them in the account's organization.
     *
     * An address that ALREADY has a subject there is reused, never re-credentialed: the
     * supplied password is dropped on the floor. Overwriting would mean "adding
     * someone's email to an account you control resets their password", which is account
     * takeover with extra steps. They keep the credential they already had; the account
     * membership is what is new.
     *
     * With no platform root (the very first install) there is nowhere for the subject to
     * live, so the member stays unlinked and falls back to the local hash. That window
     * closes as soon as the install stamps a default environment.
     */
    private function attachSubject(AccountMember $member, string $password, bool $active): void
    {
        $organizationId = Account::query()->whereKey($member->account_id)->value('organization_id');

        // BOTH the subject and the membership are written inside the platform root's
        // scope. Memberships are environment-owned too, so adding one under the ambient
        // scope would file the person's place in the account's organization under
        // whatever environment happened to be current — invisible where it is read, and
        // a row inside a tenant that has no business holding it.
        $subjectId = $this->platformRoot->run(function () use ($member, $password, $active, $organizationId): string {
            $existing = $this->subjects->findByEmail($member->email);
            $subjectId = $existing?->id;

            if ($subjectId === null) {
                $subject = $this->subjects->create($member->email, $member->name, $password);
                $subjectId = $subject->id;

                if (! $active) {
                    $this->subjects->deactivate($subjectId);
                }
            }

            if (is_string($organizationId) && $organizationId !== '') {
                // Placement, not authorization. The membership is what puts the person
                // inside the account's organization — which is what makes account SSO an
                // ordinary connection on that org, and what domain verification scopes
                // to. It carries a neutral role deliberately: AccountRole on the member
                // is the single authority for account capabilities, and mirroring it here
                // would create a second truth that drifts (and a last-owner deadlock the
                // moment ownership is transferred).
                $this->memberships->add($organizationId, $subjectId, MembershipRole::Member->value);
            }

            return $subjectId;
        });

        if ($subjectId === null) {
            return;
        }

        $member->forceFill(['subject_id' => $subjectId])->save();
    }

    public function setRole(string $id, AccountRole $role): void
    {
        $member = $this->find($id);

        if ($member === null) {
            return;
        }

        $member->role = $role;

        // A role that can't be scoped (owner/admin) always spans every environment —
        // clear any stale grants so the state can't lie.
        if (! $role->supportsEnvironmentScoping()) {
            $member->all_environments = true;
            $member->save();
            $member->environments()->detach();

            return;
        }

        $member->save();
    }

    public function setEnvironmentAccess(string $id, bool $all, array $environmentIds = []): void
    {
        $member = $this->find($id);

        if ($member === null) {
            return;
        }

        // Owners/admins are never scoped — their access is the whole account.
        if (! $member->role->supportsEnvironmentScoping()) {
            return;
        }

        $member->all_environments = $all;
        $member->save();

        if ($all) {
            $member->environments()->detach();

            return;
        }

        // Only sync grants for environments the account actually owns — never leak a
        // grant to another account's environment.
        $ownEnvironmentIds = Environment::query()
            ->where('account_id', $member->account_id)
            ->whereIn('id', $environmentIds)
            ->pluck('id')
            ->all();

        $member->environments()->sync($ownEnvironmentIds);
    }

    public function accessibleEnvironmentIds(AccountMember $member): array
    {
        $ids = $member->all_environments
            ? Environment::query()->where('account_id', $member->account_id)->pluck('id')
            : $member->environments()->pluck('environments.id');

        $out = [];

        foreach ($ids as $id) {
            if (is_string($id)) {
                $out[] = $id;
            }
        }

        return $out;
    }

    public function activate(string $id, string $password): bool
    {
        $member = $this->find($id);

        // Only an invited member can be activated — a replayed accept must never
        // reset an already-active member's password.
        if ($member === null || $member->status !== AccountMemberStatus::Invited) {
            return false;
        }

        $member->forceFill(['password' => $password, 'status' => AccountMemberStatus::Active])->save();

        // The subject is the credential of record, so acceptance writes there. Only for
        // the subject this invitation minted (still deactivated): an invitee who ALREADY
        // had a Cbox ID subject is simply activated into the account — accepting an
        // invitation must never rewrite the password of an identity that predates it.
        $this->onSubject($member, function (string $subjectId) use ($password): void {
            if ($this->subjects->isActive($subjectId)) {
                return;
            }

            $this->subjects->setPassword($subjectId, $password);
            $this->subjects->reactivate($subjectId);
        });

        return true;
    }

    public function remove(string $id): bool
    {
        $member = $this->find($id);

        // An owner can't simply be removed — that could orphan the account. Transfer
        // ownership first.
        if ($member === null || $member->role === AccountRole::Owner) {
            return false;
        }

        $subjectId = $member->subject_id;
        $accountOrganizationId = $member->account?->organization_id;

        $member->delete();

        if ($subjectId === null) {
            return true;
        }

        // Both reads/writes run in the platform root's scope, for the same reason the
        // writes did: identity and membership rows are environment-owned.
        $this->platformRoot->run(function () use ($subjectId, $accountOrganizationId): bool {
            // Losing an account membership must actually revoke the person's place in
            // the account's organization, or the removal is cosmetic: the org is what
            // account SSO and domain verification are scoped to.
            if ($accountOrganizationId !== null) {
                $this->memberships->remove($accountOrganizationId, $subjectId);
            }

            // The subject exists to be this account's member. Deactivate it — UNLESS the
            // same person is a member of another account, in which case it is still a
            // live identity and killing it would lock them out of a workspace they hold.
            if (AccountMember::query()->where('subject_id', $subjectId)->doesntExist()) {
                $this->subjects->deactivate($subjectId);
            }

            return true;
        });

        return true;
    }

    public function transferOwnership(string $accountId, string $newOwnerId): void
    {
        DB::transaction(function () use ($accountId, $newOwnerId): void {
            $newOwner = AccountMember::query()
                ->whereKey($newOwnerId)
                ->where('account_id', $accountId)
                ->where('status', 'active')
                ->lockForUpdate()
                ->first();

            if ($newOwner === null) {
                return;
            }

            // Demote the current owner(s) to admin — they keep full management access
            // but no longer own the account.
            AccountMember::query()
                ->where('account_id', $accountId)
                ->where('role', AccountRole::Owner->value)
                ->whereKeyNot($newOwnerId)
                ->update(['role' => AccountRole::Admin->value]);

            $newOwner->forceFill(['role' => AccountRole::Owner, 'all_environments' => true])->save();
            $newOwner->environments()->detach();
        });
    }

    public function resetPassword(string $id, string $password): bool
    {
        $member = $this->find($id);

        // Only an already-active member resets — never an invited one (which would
        // bypass the accept flow) or a suspended one.
        if ($member === null || ! $member->isActive()) {
            return false;
        }

        // Bump the security stamp: every existing session AND any other outstanding
        // reset link bound to the old version is invalidated (log-out-everywhere +
        // single-use reset).
        $member->forceFill([
            'password' => $password,
            'session_version' => $member->session_version + 1,
        ])->save();

        $this->onSubject($member, fn (string $subjectId) => $this->subjects->setPassword($subjectId, $password));

        return true;
    }

    public function verifyPassword(string $id, string $password): bool
    {
        $member = $this->find($id);

        // Status gate travels with the credential check: a suspended member
        // never authenticates, even with the correct password.
        if ($member === null || ! $member->isActive()) {
            // Constant-cost dummy verify so a missing/suspended member takes the
            // same time as a real one — no enumeration timing oracle.
            $this->hasher->check($password, $this->dummyHash());

            return false;
        }

        $subjectId = $member->subject_id;

        if ($subjectId === null) {
            // BOOTSTRAP ONLY: no platform root existed when this member was created, so
            // there was nowhere to put their subject. The local hash is the credential
            // until the deployment has a root. Every other path goes to the subject.
            return $this->hasher->check($password, $member->password);
        }

        $verified = $this->platformRoot->run(
            // Both gates, and in this order: a deactivated subject (an unaccepted
            // invitation, a removed member still holding a session) never authenticates,
            // and the dummy verify keeps that refusal the same cost as a wrong password.
            fn (): bool => $this->subjects->isActive($subjectId)
                ? $this->subjects->verifyPassword($subjectId, $password)
                : ! $this->hasher->check($password, $this->dummyHash()),
        );

        return $verified === true;
    }

    /**
     * Run something against the member's subject inside the platform root's scope, if
     * they have one. A member with no subject is the bootstrap case — a silent no-op, so
     * callers never have to branch on it.
     *
     * @param  Closure(string): void  $callback
     */
    private function onSubject(AccountMember $member, Closure $callback): void
    {
        $subjectId = $member->subject_id;

        if ($subjectId === null) {
            return;
        }

        $this->platformRoot->run(function () use ($subjectId, $callback): bool {
            $callback($subjectId);

            return true;
        });
    }

    public function touchLogin(string $id): void
    {
        AccountMember::query()->whereKey($id)->update(['last_login_at' => now()]);
    }

    public function forAccount(string $accountId): Collection
    {
        return AccountMember::query()
            ->where('account_id', $accountId)
            ->orderBy('created_at')
            ->get();
    }

    private ?string $dummyHash = null;

    /** A valid hash of an unguessable value, used to equalize miss-path timing. */
    private function dummyHash(): string
    {
        return $this->dummyHash ??= $this->hasher->make('cbox-id::no-such-member');
    }
}
