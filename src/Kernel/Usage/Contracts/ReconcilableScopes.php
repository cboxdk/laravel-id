<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Contracts;

/**
 * The set of scopes (organizations) the usage reconciler should sweep. The Usage
 * kernel owns metering and drift correction but must not know how the host models
 * an "organization" — so it depends on this contract for the list of metered
 * scopes, and a domain module (Organization) binds the implementation that knows
 * where those ids live. This keeps the kernel→domain dependency pointing the right
 * way: the domain depends on the kernel, never the reverse.
 */
interface ReconcilableScopes
{
    /**
     * The ids of every organization whose usage should be reconciled against
     * ground truth. Empty when there are none.
     *
     * @return list<string>
     */
    public function meteredOrganizationIds(): array;
}
