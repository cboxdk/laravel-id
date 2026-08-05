<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Enums\AccountRole;
use Cbox\Id\Platform\Models\AccountApiKey;
use Cbox\Id\Platform\ValueObjects\IssuedAccountApiKey;
use DateTimeInterface;
use Illuminate\Support\Collection;

/**
 * Repository for account API keys — the management-plane machine credential. Never
 * environment-scoped: an account key operates above every environment the account
 * owns.
 */
interface AccountApiKeys
{
    /**
     * Issue a new key. Returns the stored record plus the one-time plaintext, which
     * is never recoverable afterwards. The key carries a role that bounds what it
     * can do, and an optional expiry.
     */
    public function issue(string $accountId, string $name, AccountRole $role, ?DateTimeInterface $expiresAt = null): IssuedAccountApiKey;

    /**
     * Resolve a presented plaintext token to its active key, recording use. Returns
     * null for an unknown, revoked, or expired token — the caller learns nothing
     * more than "not valid".
     */
    public function resolve(string $plaintext): ?AccountApiKey;

    /** Revoke a key immediately (idempotent). */
    public function revoke(string $id): void;

    /**
     * Every key issued for an account (including revoked/expired, for the audit
     * list), newest first.
     *
     * @return Collection<int, AccountApiKey>
     */
    public function forAccount(string $accountId): Collection;
}
