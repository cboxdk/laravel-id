<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\Models\Project;

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
     * Provision a new account. `$environmentLimit` seeds the account's first
     * ("Default") project's environment allowance — billing/limits live on the
     * {@see Project}, so this is only the starting value.
     */
    public function create(string $name, int $environmentLimit = 2): Account;

    /**
     * @deprecated The enforced allowance moved to the project; use
     *   {@see Projects::remainingEnvironments()}. This account-level tally (limit
     *   minus ALL environments across every project) is retained only for back-compat
     *   and MISREPORTS capacity for a multi-project account — do not gate on it.
     */
    public function remainingEnvironments(Account $account): int;
}
