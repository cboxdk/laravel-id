<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Concerns;

use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantOwned;
use Cbox\Id\Kernel\Tenancy\Exceptions\CrossTenantAccess;
use Cbox\Id\Kernel\Tenancy\Scopes\TenantScope;

/**
 * Applies mandatory tenant scoping to an Eloquent model.
 *
 * Models using this trait MUST also implement
 * {@see TenantOwned}.
 *
 * Behaviour:
 *  - reads are constrained to the current tenant by {@see TenantScope};
 *  - on create, the tenant column is auto-filled from the current tenant;
 *  - on any write, a mismatch between the model's tenant and the current
 *    tenant throws {@see CrossTenantAccess} — you cannot persist a row for a
 *    tenant other than the one you are acting as (unless scoping is suspended).
 *
 * @phpstan-require-implements TenantOwned
 */
trait BelongsToTenant
{
    public static function bootBelongsToTenant(): void
    {
        static::addGlobalScope(new TenantScope(app(TenantContext::class)));

        static::saving(static function (self $model): void {
            $context = app(TenantContext::class);

            if ($context->isScopingSuspended() || ! $context->has()) {
                return;
            }

            $column = $model->tenantColumn();
            $currentKey = $context->requireTenant()->tenantKey();
            $value = $model->getAttribute($column);

            if ($value === null || $value === '') {
                $model->setAttribute($column, $currentKey);

                return;
            }

            // The tenant column always holds a string identifier; anything else,
            // or any mismatch, is a cross-tenant write and must be refused.
            if (! is_string($value) || $value !== $currentKey) {
                throw CrossTenantAccess::forWrite(
                    static::class,
                    is_string($value) ? $value : get_debug_type($value),
                    $currentKey,
                );
            }
        });
    }

    public function tenantColumn(): string
    {
        return 'organization_id';
    }
}
