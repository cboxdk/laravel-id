<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Enums\GrantSource;

/**
 * The veto seam on role assignment.
 *
 * `RoleService::assign()` calls itself the chokepoint every caller funnels through, and
 * it is — for OWNERSHIP. Conflict rules were a different story: segregation of duties was
 * enforced by the host, in front of the console's four manual grant paths, and the one
 * path the host cannot get in front of is the one inside the framework. So a directory
 * group→role mapping could create a toxic pair the console would have refused, silently,
 * on the next reconcile — and the automation a customer buys the product for was the way
 * around the control they bought it for.
 *
 * Moving the check INTO `assign()` is the fix, but it cannot be a direct dependency:
 * `Governance` already depends on `AccessControl`, so pointing `AccessControl` back at
 * `Governance` would close a cycle between two domain modules. Hence this contract —
 * `AccessControl` depends only on its own interface, and `Governance` binds the
 * implementation. The direction is preserved and the gate becomes unmissable.
 *
 * The default binding permits everything. That is deliberate: a framework that refuses
 * grants nobody configured a policy for would be a surprise, and the shipped
 * implementation is registered by `GovernanceServiceProvider`, so simply having
 * governance loaded closes the path.
 */
interface GrantGuard
{
    /**
     * Why this grant must not happen, or null to allow it.
     *
     * The reason is a human-readable sentence, because every caller either shows it to
     * someone or writes it into an audit entry that someone reads later.
     */
    public function refuse(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): ?string;
}
