<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Scopes;

use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

/**
 * Global scope that constrains every query on a tenant-owned model to the
 * current tenant.
 *
 * Security posture: deny-by-default. When scoping is active but NO tenant is
 * set, the scope matches zero rows rather than every row — a missing tenant
 * must never leak another tenant's data. Cross-tenant reads are therefore
 * impossible unless scoping is explicitly suspended via
 * {@see TenantContext::withoutScope()}.
 */
final class TenantScope implements Scope
{
    public function __construct(private readonly TenantContext $context) {}

    public function apply(Builder $builder, Model $model): void
    {
        if ($this->context->isScopingSuspended()) {
            return;
        }

        if (! $model instanceof TenantOwned) {
            return;
        }

        $column = $model->qualifyColumn($model->tenantColumn());

        // Bounded roll-up: reads constrained to an explicit, authorized set.
        $keys = $this->context->activeScopeKeys();

        if ($keys !== null) {
            if ($keys === []) {
                // Deny-by-default: empty set => no rows.
                $builder->whereRaw('1 = 0');
            } else {
                $builder->whereIn($column, $keys);
            }

            return;
        }

        $tenant = $this->context->current();

        if ($tenant === null) {
            // Deny-by-default: no tenant in context => no rows.
            $builder->whereRaw('1 = 0');

            return;
        }

        $builder->where($column, '=', $tenant->tenantKey());
    }
}
