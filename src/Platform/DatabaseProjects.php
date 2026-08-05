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
            'slug' => $this->uniqueSlug('account_id', $accountId, $name),
            'status' => ProjectStatus::Active,
            'environment_limit' => max(1, $environmentLimit),
        ]);
    }

    /**
     * Create a project an ORGANIZATION owns outright, with no account behind it.
     *
     * The account plane is being folded into the organization, and this is the write that
     * makes the fold reachable rather than merely permitted: `2026_08_07_000100` stopped
     * `projects.account_id` requiring a value, which by itself only means no statement in
     * the codebase could produce such a row.
     *
     * `account_id` is left unset rather than written as an empty string. The column is
     * nullable now and NULL is what "no account owns this" means; '' would satisfy the
     * column, fail the foreign key on any engine that checks it, and read as an account id
     * to every `where('account_id', ...)` that compares without a null check.
     *
     * The slug is unique within the ORGANIZATION here, against the `(organization_id,
     * slug)` key `2026_08_06_000100` added — not within the account, which there is none
     * of. {@see uniqueSlug()} takes the column it scopes to for exactly this reason: two
     * owners, one rule, and no second copy of the loop to drift.
     */
    public function createForOrganization(string $organizationId, string $name, int $environmentLimit = 2): Project
    {
        return Project::query()->create([
            'organization_id' => $organizationId,
            'name' => $name,
            'slug' => $this->uniqueSlug('organization_id', $organizationId, $name),
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
     * A slug derived from the name, made unique WITHIN ITS OWNER — two owners may each
     * have a "default" project, one owner may not have two.
     *
     * Takes the owning COLUMN because there are two owners now, each with its own unique
     * key: `(account_id, slug)` from the original table and `(organization_id, slug)` from
     * `2026_08_06_000100`. Scoping the loop to the wrong one produces a slug that passes
     * the check and then violates the index, which surfaces as a database error on a
     * perfectly ordinary "create a second project called Default".
     *
     * @param  'account_id'|'organization_id'  $ownerColumn
     */
    private function uniqueSlug(string $ownerColumn, string $ownerId, string $name): string
    {
        $base = Str::slug($name);
        $base = $base !== '' ? $base : 'project';

        $slug = $base;
        $n = 2;
        while (Project::query()->where($ownerColumn, $ownerId)->where('slug', $slug)->exists()) {
            $slug = $base.'-'.$n;
            $n++;
        }

        return $slug;
    }
}
