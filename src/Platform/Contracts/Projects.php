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

    /**
     * @deprecated Carries no owner, so the fence lives in the caller. Use
     *             {@see renameForOrganization()}, which puts it in the query.
     */
    public function rename(string $id, string $name): void;

    /**
     * Rename a project THIS organization owns; a foreign id is a silent no-op.
     *
     * `Project` is the one model in the hierarchy with no global scope at all — it sits
     * above the environment and below the organization, so neither `EnvironmentScope` nor
     * `TenantScope` applies — which makes `whereKey($id)->update(...)` a global write over
     * every customer's projects. Nothing reaches it today: all three console call sites
     * re-resolve the project with an organization predicate first. That is a fence four
     * call sites away from being gone, over a signature that invites the mistake, and this
     * console has already shipped exactly that bug once.
     */
    public function renameForOrganization(string $organizationId, string $id, string $name): void;

    /** @deprecated Use {@see suspendForOrganization()} — see {@see renameForOrganization()}. */
    public function suspend(string $id): void;

    public function suspendForOrganization(string $organizationId, string $id): void;

    /** @deprecated Use {@see reactivateForOrganization()} — see {@see renameForOrganization()}. */
    public function reactivate(string $id): void;

    public function reactivateForOrganization(string $organizationId, string $id): void;

    /**
     * How many more environments this project's plan allows (limit minus the ones it
     * already holds), never negative.
     */
    public function remainingEnvironments(Project $project): int;
}
