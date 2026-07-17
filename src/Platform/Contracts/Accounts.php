<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Models\Account;

/**
 * Repository for accounts — the customer workspaces that own environments. Never
 * environment-scoped: an account sits above the boundary, so these lookups are
 * global regardless of which environment is pinned for the request.
 */
interface Accounts
{
    public function find(string $id): ?Account;

    /** Rename an account (its display name across the workspace console). */
    public function rename(string $id, string $name): void;

    /**
     * Suspend an account: its members can no longer sign in, its API keys stop
     * resolving, and every environment it owns stops serving auth. The platform's
     * off-switch for a delinquent or abusive tenant. Idempotent.
     */
    public function suspend(string $id): void;

    /** Reactivate a suspended account. Idempotent. */
    public function reactivate(string $id): void;

    /**
     * Provision a new account. `$environmentLimit` is the plan's environment
     * allowance; the default matches the standard one-prod-one-staging shape.
     */
    public function create(string $name, int $environmentLimit = 2): Account;

    /**
     * How many more environments this account may create under its plan. Zero
     * means the limit is reached; a negative result is clamped to zero.
     */
    public function remainingEnvironments(Account $account): int;
}
