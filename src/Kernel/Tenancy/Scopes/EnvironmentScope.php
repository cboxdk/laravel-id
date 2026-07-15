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
    public function apply(Builder $builder, Model $model): void
    {
        // Resolve the context LAZILY, per query — never capture it. The binding is
        // `scoped`, so a queue worker gets a fresh EnvironmentContext per job; a
        // global scope is registered once at model-boot, so a captured instance
        // would go stale after the first job and read the wrong (or no) environment.
        // Resolving here keeps the read scope in lock-step with the write hook in
        // BelongsToEnvironment::saving(), which already resolves it per call.
        $context = app(EnvironmentContext::class);

        if ($context->isScopingSuspended()) {
            return;
        }

        if (! $model instanceof EnvironmentOwned) {
            return;
        }

        $column = $model->qualifyColumn($model->environmentColumn());
        $environment = $context->current();

        if ($environment === null) {
            // Deny-by-default: no environment in context => no rows.
            $builder->whereRaw('1 = 0');

            return;
        }

        $builder->where($column, '=', $environment->environmentKey());
    }
}
