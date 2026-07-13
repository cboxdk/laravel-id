<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Scopes;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Scope;

/**
 * Global scope that constrains every query on an environment-owned model to the
 * current environment — the HARD outer boundary.
 *
 * Deny-by-default: when the scope is active but NO environment is set, it matches
 * zero rows rather than every row. It is INDEPENDENT of the organization-level
 * tenant scope: suspending or rolling up the org dimension
 * (TenantContext::withoutScope / scopedTo) does NOT relax this one. Only the
 * provisioning-only {@see EnvironmentContext::withoutScope()} suspends it.
 *
 * @implements Scope<Model>
 */
final class EnvironmentScope implements Scope
{
    public function __construct(private readonly EnvironmentContext $context) {}

    public function apply(Builder $builder, Model $model): void
    {
        if ($this->context->isScopingSuspended()) {
            return;
        }

        if (! $model instanceof EnvironmentOwned) {
            return;
        }

        $column = $model->qualifyColumn($model->environmentColumn());
        $environment = $this->context->current();

        if ($environment === null) {
            // Deny-by-default: no environment in context => no rows.
            $builder->whereRaw('1 = 0');

            return;
        }

        $builder->where($column, '=', $environment->environmentKey());
    }
}
