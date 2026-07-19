<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\Models\Project;
use Illuminate\Support\Collection;

/**
 * Projects — the IdP-product layer inside an account. Queries are global (a project
 * owns environments, it does not live inside one). The plan/billing anchor lives on
 * the project, so its `environment_limit` gates how many environments it may hold.
 */
interface Projects
{
    public function find(string $id): ?Project;

    /**
     * Every project belonging to an account, oldest first.
     *
     * @return Collection<int, Project>
     */
    public function forAccount(string $accountId): Collection;

    /**
     * Create a project under an account. The slug is derived from the name and made
     * unique within that account.
     */
    public function create(string $accountId, string $name, int $environmentLimit = 2): Project;

    public function rename(string $id, string $name): void;

    public function suspend(string $id): void;

    public function reactivate(string $id): void;

    /**
     * How many more environments this project's plan allows (limit minus the ones it
     * already holds), never negative.
     */
    public function remainingEnvironments(Project $project): int;
}
