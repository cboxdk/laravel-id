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
 * `organization_id` is the third tier of ownership, and the only one a TENANT authors:
 * null means the row is shared with every organization in its environment (what the
 * environment-plane form writes, and what every row predating the column is), and a value
 * means exactly one tenant may see, bind, edit or delete it. It has NO global scope,
 * because nothing in the console populates {@see TenantContext} and a deny-by-default
 * scope resolved from an empty context would hide the shared tier from everybody. The
 * fence is {@see self::scopeVisibleToOrganization()} and
 * {@see self::scopeOwnedByOrganization()} — named so the rule has one implementation
 * rather than one per page that remembers to write it.
 *
 * @property string $id
 * @property string|null $client_id
 * @property string|null $environment_id
 * @property string|null $organization_id
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

            // No environment resolved and scoping NOT suspended: fall back to the
            // platform-global rows only. Returning unconstrained here failed OPEN — a
            // permission key is tenant-identifying (`acme.billing.refund` names the
            // customer and what they bought), and every other environment-owned model
            // fails closed in this state (EnvironmentScope emits `1 = 0`). Suspension
            // stays the ONE explicit way to read the whole catalog, so operator and
            // manifest-sync paths keep working through the branch above.
            if ($environment === null) {
                $query->whereNull($query->qualifyColumn('environment_id'));

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
     * What an organization may SEE: its own rows, plus the environment's shared tier.
     *
     * A null organization is the environment plane (and operator tooling), which sees the
     * shared tier ONLY. That is narrower than it could be — an environment administrator
     * arguably owns everything in their environment — and it is the deliberate direction:
     * a tenant's `feature:action` keys name what that tenant bought (`acme.billing.refund`
     * is a customer list one row at a time), and the console has no page that needs to
     * read them. Widening later is a query; unreading a disclosure is not.
     *
     * @param  Builder<self>  $query
     */
    public function scopeVisibleToOrganization(Builder $query, ?string $organizationId): void
    {
        if ($organizationId === null) {
            $query->whereNull($query->qualifyColumn('organization_id'));

            return;
        }

        $query->where(function (Builder $inner) use ($organizationId): void {
            $inner->whereNull($inner->qualifyColumn('organization_id'))
                ->orWhere($inner->qualifyColumn('organization_id'), $organizationId);
        });
    }

    /**
     * What an organization may WRITE: exactly its own rows, never the shared tier.
     *
     * Not the same predicate as {@see self::scopeVisibleToOrganization()}, and the
     * difference is the whole point. Visibility includes the shared tier because roles are
     * composed from it; authorship must not, or a tenant editing a key they can see would
     * be editing every peer's catalog — and deleting one cascades `role_permission` for
     * every role in the environment.
     *
     * @param  Builder<self>  $query
     */
    public function scopeOwnedByOrganization(Builder $query, ?string $organizationId): void
    {
        if ($organizationId === null) {
            $query->whereNull($query->qualifyColumn('organization_id'));

            return;
        }

        $query->where($query->qualifyColumn('organization_id'), $organizationId);
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
