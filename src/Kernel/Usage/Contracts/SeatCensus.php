<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Contracts;

/**
 * Ground truth for the seat dimension: how many seats a metered scope currently
 * occupies. The Usage kernel reconciles the meter against this number but must not
 * know how the host models membership — what a "seat" is, or which membership states
 * count as occupying one, belongs to the domain that owns memberships.
 *
 * Paired with {@see ReconcilableScopes} (which scopes to sweep), this keeps the
 * kernel→domain dependency pointing the right way: the domain depends on the kernel,
 * never the reverse.
 */
interface SeatCensus
{
    /**
     * The number of seats currently occupied in the given scope — the authority the
     * metered count is reconciled against. Zero when the scope holds none.
     */
    public function activeSeats(string $organizationId): int;
}
