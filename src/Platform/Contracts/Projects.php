<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Models\Project;

/**
 * Projects — the IdP-product layer an organization owns. Queries are global (a project
 * owns environments, it does not live inside one). The plan/billing anchor lives on
 * the project, so its `environment_limit` gates how many environments it may hold.
 */
interface Projects
{
    public function find(string $id): ?Project;

    /** Create a project an organization owns. The only writer. */
    public function createForOrganization(string $organizationId, string $name, int $environmentLimit = 2): Project;

    public function rename(string $id, string $name): void;

    public function suspend(string $id): void;

    public function reactivate(string $id): void;

    /**
     * How many more environments this project's plan allows (limit minus the ones it
     * already holds), never negative.
     */
    public function remainingEnvironments(Project $project): int;
}
