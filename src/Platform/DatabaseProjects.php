<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\OrganizationProjects;
use Cbox\Id\Platform\Contracts\Projects;
use Cbox\Id\Platform\Enums\ProjectStatus;
use Cbox\Id\Platform\Models\Project;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * Eloquent-backed projects. No environment scope is ever applied — a project owns
 * environments, it does not live inside one — so these queries are global.
 */
class DatabaseProjects implements OrganizationProjects, Projects
{
    public function find(string $id): ?Project
    {
        return Project::query()->whereKey($id)->first();
    }

    /**
     * @return Collection<int, Project>
     */
    public function forOrganization(string $organizationId): Collection
    {
        return Project::query()
            ->where('organization_id', $organizationId)
            ->orderBy('created_at')
            ->get();
    }

    public function ownedByOrganization(string $projectId, string $organizationId): bool
    {
        // Asked of the DATABASE rather than by loading the row and comparing: an empty
        // owner id must never match, and a PHP-side `===` against an attribute is one
        // forgotten guard away from answering "owned" for a project owned by nobody.
        return $organizationId !== '' && Project::query()
            ->whereKey($projectId)
            ->where('organization_id', $organizationId)
            ->exists();
    }

    /**
     * Create a project an organization owns.
     *
     * The ONLY writer. There was a second, `create(string $accountId, …)`, which wrote an
     * `account_id` and let a model hook derive the organization from it — two ways to
     * create the same row, and the derived one was the authority for ownership while the
     * passed one was the authority for billing. The owner is passed in now, and there is
     * nowhere left to write a project whose owner is inferred.
     */
    public function createForOrganization(string $organizationId, string $name, int $environmentLimit = 2): Project
    {
        return Project::query()->create([
            'organization_id' => $organizationId,
            'name' => $name,
            'slug' => $this->uniqueSlug($organizationId, $name),
            'status' => ProjectStatus::Active,
            'environment_limit' => max(1, $environmentLimit),
        ]);
    }

    public function rename(string $id, string $name): void
    {
        Project::query()->whereKey($id)->update(['name' => $name]);
    }

    public function suspend(string $id): void
    {
        Project::query()->whereKey($id)->update(['status' => ProjectStatus::Suspended]);
    }

    public function reactivate(string $id): void
    {
        Project::query()->whereKey($id)->update(['status' => ProjectStatus::Active]);
    }

    public function remainingEnvironments(Project $project): int
    {
        $used = Environment::query()->where('project_id', $project->id)->count();

        return max(0, $project->environment_limit - $used);
    }

    /**
     * A slug derived from the name, unique WITHIN THE OWNING ORGANIZATION — two customers
     * may each have a "default" product, one customer may not have two.
     *
     * It took an owner COLUMN for a while, because there were two owners with two unique
     * keys: `(account_id, slug)` and `(organization_id, slug)`. Scoping the loop to the
     * wrong one produced a slug that passed the check and then violated the index, on an
     * ordinary second product called "Default". One owner, one key, no parameter.
     */
    private function uniqueSlug(string $organizationId, string $name): string
    {
        $base = Str::slug($name);
        $base = $base !== '' ? $base : 'project';

        $slug = $base;
        $n = 2;
        while (Project::query()->where('organization_id', $organizationId)->where('slug', $slug)->exists()) {
            $slug = $base.'-'.$n;
            $n++;
        }

        return $slug;
    }
}
