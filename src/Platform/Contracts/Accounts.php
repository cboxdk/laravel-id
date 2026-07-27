<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Organization\Contracts\Organizations;
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
     *
     * `$actorId` attributes the action to the operator who performed it, and the
     * audit entry is written HERE — matching {@see Organizations::suspend()} and
     * {@see PlatformOperators::suspend()}. Until v0.64.0 this took `($id)` alone and
     * audited nothing, which pushed the entry out to the call site where a second
     * caller could silently omit it; the broadest access revocation the platform has
     * was the one state change with no guaranteed trail.
     */
    public function suspend(string $id, string $actorId): void;

    /**
     * Reactivate a suspended account, restoring sign-in and key resolution across
     * every environment it owns. Idempotent, audited, and actor-attributed for the
     * same reason as {@see self::suspend()} — "who lifted this suspension" is the
     * other half of the question the trail has to answer.
     */
    public function reactivate(string $id, string $actorId): void;

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
