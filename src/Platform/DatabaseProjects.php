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
    public function forAccount(string $accountId): Collection
    {
        return Project::query()
            ->where('account_id', $accountId)
            ->orderBy('created_at')
            ->get();
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
        // Asked of the DATABASE rather than by loading the row and comparing: SQL's
        // NULL comparison already refuses a project with no organization, where a
        // PHP-side `===` against a nullable attribute is one forgotten null-check away
        // from answering "owned" for a project owned by nobody. The empty-string guard
        // covers the other end — a missing organization id arriving as '' must not be
        // allowed to match a column that somehow holds one.
        return $organizationId !== '' && Project::query()
            ->whereKey($projectId)
            ->where('organization_id', $organizationId)
            ->exists();
    }

    public function create(string $accountId, string $name, int $environmentLimit = 2): Project
    {
        return Project::query()->create([
            'account_id' => $accountId,
            'name' => $name,
            'slug' => $this->uniqueSlug($accountId, $name),
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
     * A slug derived from the name, made unique WITHIN the account (two accounts may
     * each have a "default" project).
     */
    private function uniqueSlug(string $accountId, string $name): string
    {
        $base = Str::slug($name);
        $base = $base !== '' ? $base : 'project';

        $slug = $base;
        $n = 2;
        while (Project::query()->where('account_id', $accountId)->where('slug', $slug)->exists()) {
            $slug = $base.'-'.$n;
            $n++;
        }

        return $slug;
    }
}
