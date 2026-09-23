<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Models;

use Cbox\Id\AccessControl\Enums\RoleSource;
use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A role. `organization_id` null = a system role reusable across orgs within the
 * owning environment. A non-null `client_id` marks an APP-DECLARED role (from that
 * app's manifest, `source = manifest`) — keyed by its stable `key` slug and
 * read-only in the console. `orphaned_at` is set when the declaring app drops the
 * role from a later manifest; the row (and any assignments) are kept, not deleted.
 *
 * `tenant_assignable` false marks a STAFF role — the app vendor's own support people and
 * administrators. It is never offered to, nor accepted from, the tenant plane (see
 * {@see self::scopeTenantAssignable()} and `Roles::assertTenantAssignable()`); an
 * environment administrator may still grant it, environment-wide or inside one org.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string|null $client_id
 * @property string $name
 * @property string|null $key
 * @property string|null $description
 * @property bool $tenant_assignable
 * @property RoleSource $source
 * @property Carbon|null $orphaned_at
 */
class Role extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'roles';

    protected $guarded = [];

    /**
     * The roles a TENANT administrator of this organization may grant: the
     * organization's own roles plus the environment's shared ones, minus staff-only and
     * orphaned roles. Narrowed to one app (plus the app-agnostic ones) when `$clientId`
     * is given.
     *
     * One predicate, shared by the list a tenant plane renders and the guard that refuses
     * a write, so the two cannot drift: a role the picker hides is exactly a role the
     * write path refuses.
     *
     * @param  Builder<self>  $query
     */
    public function scopeTenantAssignable(Builder $query, string $organizationId, ?string $clientId = null): void
    {
        $query
            ->where(fn (Builder $inner) => $inner
                ->whereNull($inner->qualifyColumn('organization_id'))
                ->orWhere($inner->qualifyColumn('organization_id'), $organizationId))
            ->where($query->qualifyColumn('tenant_assignable'), true)
            ->whereNull($query->qualifyColumn('orphaned_at'))
            ->when($clientId !== null, fn (Builder $inner) => $inner->where(fn (Builder $app) => $app
                ->whereNull($app->qualifyColumn('client_id'))
                ->orWhere($app->qualifyColumn('client_id'), $clientId)));
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'source' => RoleSource::class,
            'tenant_assignable' => 'boolean',
            'orphaned_at' => 'datetime',
        ];
    }
}
