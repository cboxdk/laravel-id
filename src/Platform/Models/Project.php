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
 * A project — one IdP product within an account, between the account (the login /
 * identity umbrella) and its environments (the product's prod/staging/dev stages).
 * The layer other IdPs call an "application" or a "tenant": one account can own several
 * independently-billed projects.
 *
 * The plan/billing anchor lives here: `environment_limit` is THIS project's plan
 * allowance, and a future subscription attaches to the project — so two products
 * under one account bill separately. Like the account, a project sits ABOVE
 * environments and is not environment-scoped.
 *
 * An account IS an organization in the platform-root environment (see
 * {@see Account::$organization_id}), so a project's account already implies an
 * owning organization. `organization_id` records that link DIRECTLY, so ownership
 * can be read from the organization side ({@see Organization::projects()}) without
 * routing through the account plane. It is stamped automatically on create and is
 * null only where the account itself is unhomed.
 *
 * @property string $id
 * @property string $account_id
 * @property string|null $organization_id The owning organization in the platform-root
 *                                        environment. Null only when the owning account
 *                                        predates the unified-identity cutover and was
 *                                        never homed.
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
     * The account that owns this project (the login/identity umbrella above it).
     *
     * @return BelongsTo<Account, $this>
     */
    public function account(): BelongsTo
    {
        return $this->belongsTo(Account::class);
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

    /**
     * Keep the direct organization link in step with the account it is derived from.
     *
     * An account IS an organization, so this value is never independent input — it is
     * a denormalization of `accounts.organization_id`, and deriving it here rather
     * than at the call site means every path that creates a project stamps it,
     * including a host that calls `Project::create()` directly. That matters because
     * a project created after the backfill with a null organization would be
     * invisible to {@see Organization::projects()} while looking perfectly healthy
     * from the account side — a silent, one-directional split of the same fact. This
     * is the {@see Environment::booted()} pattern: the one place a new call site
     * cannot forget.
     *
     * An explicitly supplied organization is left alone (the caller knows something
     * we do not), and an unhomed account yields null rather than inventing a home.
     */
    protected static function booted(): void
    {
        static::creating(function (self $project): void {
            if ($project->getAttribute('organization_id') !== null) {
                return;
            }

            $accountId = $project->getAttribute('account_id');

            if (! is_string($accountId) || $accountId === '') {
                return;
            }

            $project->setAttribute(
                'organization_id',
                Account::query()->whereKey($accountId)->value('organization_id'),
            );
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => ProjectStatus::class,
            'environment_limit' => 'integer',
            'settings' => 'array',
        ];
    }
}
