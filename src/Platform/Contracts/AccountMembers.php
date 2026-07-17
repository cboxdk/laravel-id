<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Enums\AccountRole;
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
     * Add the account's first member — its owner. The password is hashed with the
     * configured driver on the way in; the member is created with the Owner role.
     */
    public function create(string $accountId, string $email, string $password, ?string $name = null): AccountMember;

    /**
     * Invite a member with a role: create them in the 'invited' state with no usable
     * password. An invited member cannot authenticate (status gate) until they accept
     * and set a password via {@see activate()}.
     */
    public function invite(string $accountId, string $email, AccountRole $role, ?string $name = null): AccountMember;

    /**
     * Accept an invitation: set the member's password and activate them. A no-op if
     * the member is not currently invited (so a replayed accept can't reset an
     * active member's password). Returns whether activation happened.
     */
    public function activate(string $id, string $password): bool;

    /**
     * Change a member's role. Owners/admins gain every environment (scoping is
     * meaningless for them), so switching to such a role also resets the member to
     * all-environments access.
     */
    public function setRole(string $id, AccountRole $role): void;

    /**
     * Set a member's environment access. `$all` grants every environment the account
     * owns; otherwise the member is pinned to `$environmentIds`. Only takes effect
     * for roles that support scoping — owners/admins always have every environment.
     *
     * @param  list<string>  $environmentIds
     */
    public function setEnvironmentAccess(string $id, bool $all, array $environmentIds = []): void;

    /**
     * The ids of the environments a member may reach: every environment the account
     * owns when they have all-environments access, otherwise only their granted set.
     *
     * @return list<string>
     */
    public function accessibleEnvironmentIds(AccountMember $member): array;

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
