<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A permission — a `feature:action` key. `client_id` null = an org/system-level
 * permission; a non-null `client_id` marks one an app declared through its manifest.
 * `orphaned_at` is set when the declaring app stops declaring it (kept, not deleted).
 *
 * `environment_id` scopes the catalog to the HARD environment boundary: an APP-DECLARED
 * permission carries its declaring client's environment, so an environment admin never
 * sees — nor binds a role to — another environment's declared keys. A MANUAL permission
 * keeps `environment_id` null: it is platform-global and shared across every environment
 * by design. Visibility is enforced softly (env OR null) rather than with the hard
 * {@see BelongsToEnvironment} trait, whose strict
 * `environment_id = current` would hide the intentional platform-global (null) rows.
 *
 * @property string $id
 * @property string|null $client_id
 * @property string|null $environment_id
 * @property string $name
 * @property string|null $description
 * @property bool $tenant_assignable
 * @property Carbon|null $orphaned_at
 */
class Permission extends Model
{
    use HasUlids;

    protected $table = 'permissions';

    protected $guarded = [];

    protected static function booted(): void
    {
        // Environment-visible scope: within an environment, a permission is visible
        // only when it belongs to that environment OR is platform-global (null). With
        // no environment in context — operator/system tooling, the manifest sync's
        // scope-suspended lookups — apply NO constraint so those paths still see the
        // whole catalog.
        static::addGlobalScope('environmentVisible', function (Builder $query): void {
            $context = app(EnvironmentContext::class);

            if ($context->isScopingSuspended()) {
                return;
            }

            $environment = $context->current();

            if ($environment === null) {
                return;
            }

            $environmentKey = $environment->environmentKey();

            $query->where(function (Builder $inner) use ($environmentKey): void {
                $inner->where($inner->qualifyColumn('environment_id'), $environmentKey)
                    ->orWhereNull($inner->qualifyColumn('environment_id'));
            });
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'tenant_assignable' => 'boolean',
            'orphaned_at' => 'datetime',
        ];
    }
}
