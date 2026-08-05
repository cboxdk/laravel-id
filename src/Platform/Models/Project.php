<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Models;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Platform\Enums\ProjectStatus;
use Cbox\Id\Platform\PlatformRoot;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A project — one IdP product an organization owns, between the organization (who the
 * customer is) and its environments (that product's prod/staging/dev stages). The layer
 * other IdPs call an "application" or a "tenant": one customer can own several
 * independently-billed products.
 *
 * The plan anchor lives here: `environment_limit` is THIS project's allowance and a
 * subscription attaches to the project, so two products belonging to the same customer
 * bill separately. Like the organization that owns it, a project sits ABOVE environments
 * and is not environment-scoped.
 *
 * `organization_id` is REQUIRED and set at create. It used to be nullable, stamped by a
 * `creating` hook that derived it from an `accounts` row — because ownership ran through
 * an account plane that shadowed the organization one-to-one. There is no account row and
 * no hook: the owner is passed in, and a project with no owner cannot be written.
 *
 * @property string $id
 * @property string $organization_id The owning organization, in the platform-root
 *                                   environment.
 * @property string $name
 * @property string $slug
 * @property ProjectStatus $status
 * @property int $environment_limit
 * @property array<string, mixed> $settings
 */
class Project extends Model
{
    use HasUlids;

    protected $table = 'projects';

    protected $guarded = [];

    public function isActive(): bool
    {
        return $this->status === ProjectStatus::Active;
    }

    /**
     * The environments (prod/staging/dev stages) of this project. Not
     * environment-scoped — the project is the owner, above the boundary.
     *
     * @return HasMany<Environment, $this>
     */
    public function environments(): HasMany
    {
        return $this->hasMany(Environment::class);
    }

    /**
     * The organization that owns this project — the account's home in the
     * platform-root environment.
     *
     * The related query IS environment-scoped ({@see Organization} is
     * {@see EnvironmentOwned}), so this resolves only from inside the platform root
     * and returns null anywhere else. That is the correct failure: a tenant host has
     * no business reading the row that identifies the platform's own customer, and a
     * cross-boundary read is exactly what the scope exists to refuse. Callers on the
     * platform plane already run inside the root — see {@see PlatformRoot::run()}.
     *
     * @return BelongsTo<Organization, $this>
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
