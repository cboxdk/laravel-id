<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\DatabaseProjects;
use Cbox\Id\Platform\Models\Project;
use Illuminate\Support\Collection;

/**
 * Reading IdP products from the ORGANIZATION side.
 *
 * A separate contract rather than two more methods on {@see Projects}: adding to an
 * interface breaks every host that implements it, and this package's own rule is that
 * a capability is its own interface. {@see DatabaseProjects} implements both, so
 * nothing is duplicated behind them.
 *
 * Queries are global, exactly as {@see Projects}' are — a project owns environments,
 * it does not live inside one. The organization ID is therefore the ONLY thing
 * separating one customer's products from another's here, which is why these methods
 * take an id and never a "current organization": there is no ambient answer above the
 * tenancy boundary, and inventing one is how a roll-up becomes a leak.
 */
interface OrganizationProjects
{
    /**
     * Every project the organization owns, oldest first — the organization-side
     * counterpart to {@see Projects::forAccount()}.
     *
     * Prefer {@see Organization::projects()} when the model is already loaded; this
     * exists for the common console case where only the id is in hand (from the
     * session) and loading the organization would mean entering its environment.
     *
     * @return Collection<int, Project>
     */
    public function forOrganization(string $organizationId): Collection;

    /**
     * Whether this project is owned by that organization — the ownership check to
     * make before acting on a project id that arrived from a request.
     *
     * Explicitly false for a project with no organization: an unhomed account's
     * project is owned by nobody on this side of the bridge, and "no owner" must
     * never read as "owned by whoever asked".
     */
    public function ownedByOrganization(string $projectId, string $organizationId): bool;
}
