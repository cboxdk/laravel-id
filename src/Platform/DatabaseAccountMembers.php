<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\Models\AccountMember;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * Eloquent-backed account members. Like {@see DatabasePlatformOperators}, no
 * environment scope is applied — members authenticate at the platform root,
 * above every environment — and the miss path is constant-cost so a missing or
 * suspended member is indistinguishable by timing from an active one.
 */
final class DatabaseAccountMembers implements AccountMembers
{
    public function __construct(
        private readonly Hasher $hasher,
    ) {}

    public function find(string $id): ?AccountMember
    {
        return AccountMember::query()->whereKey($id)->first();
    }

    public function findByEmail(string $email): ?AccountMember
    {
        return AccountMember::query()->where('email', $email)->first();
    }

    public function create(string $accountId, string $email, string $password, ?string $name = null): AccountMember
    {
        return AccountMember::query()->create([
            'account_id' => $accountId,
            'email' => $email,
            'name' => $name,
            // The account's first member owns it outright.
            'role' => AccountRole::Owner,
            'all_environments' => true,
            // The model's `hashed` cast hashes with the configured driver.
            'password' => $password,
            'status' => 'active',
        ]);
    }

    public function invite(string $accountId, string $email, AccountRole $role, ?string $name = null): AccountMember
    {
        return AccountMember::query()->create([
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
            'status' => 'invited',
        ]);
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
        if ($member === null || $member->status !== 'invited') {
            return false;
        }

        $member->forceFill(['password' => $password, 'status' => 'active'])->save();

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

        return $this->hasher->check($password, $member->password);
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
