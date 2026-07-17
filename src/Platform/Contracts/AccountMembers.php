<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Models\AccountMember;
use Illuminate\Support\Collection;

/**
 * Repository for account members — the login identities that administer an
 * account and its environments from the platform root. Modelled on
 * {@see PlatformOperators}: a member authenticates once at the root, above every
 * environment, so these lookups are global and never environment-scoped.
 */
interface AccountMembers
{
    public function find(string $id): ?AccountMember;

    /**
     * Look a member up by their globally-unique email — the entry point for
     * root sign-in and the answer to "which account(s) is this email on".
     */
    public function findByEmail(string $email): ?AccountMember;

    /**
     * Add a member to an account. The password is hashed with the configured
     * driver on the way in.
     */
    public function create(string $accountId, string $email, string $password, ?string $name = null): AccountMember;

    /**
     * Verify a password for a member, gated on active status — a suspended
     * member never authenticates, even with the right credential.
     */
    public function verifyPassword(string $id, string $password): bool;

    /** Record a successful sign-in timestamp. */
    public function touchLogin(string $id): void;

    /**
     * Every member of an account (the account's team roster).
     *
     * @return Collection<int, AccountMember>
     */
    public function forAccount(string $accountId): Collection;
}
