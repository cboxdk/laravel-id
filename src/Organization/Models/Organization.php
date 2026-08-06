<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Cbox\Id\Organization\Enums\OrganizationStatus;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Platform\Models\Account;
use Cbox\Id\Platform\Models\Project;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasManyThrough;

/**
 * A tenant — the isolation boundary of the platform. Organizations form a
 * management tree (reseller → customer, holding → subsidiary) via `parent_id`
 * and the `organization_closure` table.
 *
 * This is the production {@see Tenant}: its key is its own id.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $name
 * @property string $slug
 * @property string|null $parent_id
 * @property OrganizationType $type
 * @property OrganizationStatus $status
 * @property array<string, mixed> $settings
 */
class Organization extends Model implements EnvironmentOwned, Tenant
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'organizations';

    protected $guarded = [];

    public function tenantKey(): string
    {
        return $this->id;
    }

    /**
     * The IdP products this organization owns.
     *
     * An account IS an organization ({@see Account::$organization_id}), so an
     * organization in the platform root can own projects exactly as an account does;
     * this is the same ownership read one level down the bridge, and it is what lets
     * a host stop reaching for {@see Account} to answer "what does this customer own".
     * {@see Account::projects()} keeps working unchanged.
     *
     * SCOPE. This relation crosses OUT of the environment scope, and that is the
     * point: {@see Project} is not {@see EnvironmentOwned} because a project OWNS
     * environments — asking which environment it lives in is a category error, it
     * holds several. What makes the crossing safe is the parent, not the child: this
     * model IS environment-owned, so an `$organization` instance can only be obtained
     * from inside its own environment ({@see EnvironmentScope} is deny-by-default and
     * refuses it even by primary key from anywhere else), and the child query is keyed
     * on that organization's id. Reaching another tenant's projects would first require
     * reaching their organization, which the scope already prevents. This is the same
     * shape — and the same argument — as {@see Account::projects()}.
     *
     * MODULE DIRECTION. This is the first reference from Organization INTO Platform;
     * until now the dependency ran one way only. It is stated rather than hidden
     * because it is the bridge itself: the platform plane is being folded into the
     * organization, so the arrow has to turn at exactly one place, and this is it. It
     * stays a model relation and nothing more — no service in this module reaches into
     * Platform, and the reverse fold (Platform reading organizations) is unchanged.
     *
     * @return HasMany<Project, $this>
     */
    public function projects(): HasMany
    {
        return $this->hasMany(Project::class);
    }

    /**
     * The environments this organization owns, through its projects.
     *
     * Deliberately NOT a denormalized `environments.organization_id` mirroring
     * `environments.account_id`. Environments already nest under a project, so the
     * ownership fact exists once; a second column would have to be written by every
     * creation path and would drift the first time one forgot. The join costs one
     * more table and buys one source of truth.
     *
     * Environments with no project — the self-hosted deployment's single forced IdP,
     * where `project_id` is the null sentinel — belong to no organization and are
     * correctly absent here, as they are absent from {@see Account::projects()}'s
     * subtree.
     *
     * SCOPE. Same crossing, same reason as {@see projects()}: neither {@see Project}
     * nor {@see Environment} is environment-owned (an environment IS the boundary, it
     * cannot be inside one), and the environment-owned parent is what gates access.
     *
     * @return HasManyThrough<Environment, Project, $this>
     */
    public function environments(): HasManyThrough
    {
        return $this->hasManyThrough(Environment::class, Project::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => OrganizationType::class,
            'status' => OrganizationStatus::class,
            'settings' => 'array',
        ];
    }
}
