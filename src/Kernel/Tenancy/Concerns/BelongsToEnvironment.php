<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Concerns;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;

/**
 * Applies mandatory, hard environment scoping to an Eloquent model. Models using
 * this trait MUST also implement EnvironmentOwned.
 *
 *  - reads are constrained to the current environment by {@see EnvironmentScope};
 *  - on create, the environment column is auto-filled from the current environment;
 *  - on any write, a mismatch between the row's environment and the current one
 *    throws {@see CrossEnvironmentAccess} — the boundary is never crossed by a
 *    mutation (there is no cross-environment roll-up or elevation).
 *
 * A model may combine this with BelongsToTenant: the two scopes are orthogonal —
 * environment is the hard outer wall, organization the inner (roll-up-able) one.
 *
 * @phpstan-require-implements EnvironmentOwned
 */
trait BelongsToEnvironment
{
    public static function bootBelongsToEnvironment(): void
    {
        static::addGlobalScope(new EnvironmentScope);

        static::saving(static function (self $model): void {
            $context = app(EnvironmentContext::class);

            if ($context->isScopingSuspended() || ! $context->has()) {
                return;
            }

            $column = $model->environmentColumn();
            $currentKey = $context->requireEnvironment()->environmentKey();
            $value = $model->getAttribute($column);

            if ($value === null || $value === '') {
                $model->setAttribute($column, $currentKey);

                return;
            }

            if (! is_string($value) || $value !== $currentKey) {
                throw CrossEnvironmentAccess::forWrite(
                    static::class,
                    is_string($value) ? $value : get_debug_type($value),
                    $currentKey,
                );
            }
        });
    }

    public function environmentColumn(): string
    {
        return 'environment_id';
    }
}
