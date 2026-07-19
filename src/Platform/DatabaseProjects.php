<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Platform\Contracts\Projects;
use Cbox\Id\Platform\Models\Project;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * Eloquent-backed projects. No environment scope is ever applied — a project owns
 * environments, it does not live inside one — so these queries are global.
 */
final class DatabaseProjects implements Projects
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

    public function create(string $accountId, string $name, int $environmentLimit = 2): Project
    {
        return Project::query()->create([
            'account_id' => $accountId,
            'name' => $name,
            'slug' => $this->uniqueSlug($accountId, $name),
            'status' => 'active',
            'environment_limit' => max(1, $environmentLimit),
        ]);
    }

    public function rename(string $id, string $name): void
    {
        Project::query()->whereKey($id)->update(['name' => $name]);
    }

    public function suspend(string $id): void
    {
        Project::query()->whereKey($id)->update(['status' => 'suspended']);
    }

    public function reactivate(string $id): void
    {
        Project::query()->whereKey($id)->update(['status' => 'active']);
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
