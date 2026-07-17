<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Platform\Contracts\AccountMembers;
use Cbox\Id\Platform\Models\AccountMember;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Collection;

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
            // The model's `hashed` cast hashes with the configured driver.
            'password' => $password,
            'status' => 'active',
        ]);
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
