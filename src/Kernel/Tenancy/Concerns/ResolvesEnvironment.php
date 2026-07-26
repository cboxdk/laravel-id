<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Concerns;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;

/**
 * Resolve the ambient environment LAZILY, per call — never capture it.
 *
 * `EnvironmentContext` is a `scoped` binding. A `singleton` that constructor-injects it
 * captures ONE instance for the life of the process, and a queue worker's
 * `forgetScopedInstances()` between jobs unsets the BINDING without resetting the object
 * a singleton already holds. So the singleton keeps whatever the FIRST job's `set()` left
 * on it — job B is then written, read, keyed or delivered under job A's environment.
 *
 * `EnvironmentScope::apply()` has stated this rule in a comment for a long time, and it
 * was violated four separate times anyway (DatabaseEventBus, DatabaseAuditLog,
 * DatabaseKeyManager, DatabaseExternalActions). This trait exists so the correct pattern
 * is also the SHORTEST one to write — and the architecture test in
 * `tests/Feature/Kernel/Tenancy/ScopedContextCaptureTest.php` is what actually holds the
 * line, because a comment demonstrably did not.
 *
 * Not every consumer fails loudly, which is why "it works in practice" is not evidence:
 * an {@see EnvironmentOwned} model fails CLOSED (the
 * `saving()` hook re-resolves and throws `CrossEnvironmentAccess` on a mismatch), but
 * anything NOT environment-owned — an outbox row, a cache key — silently takes the stale
 * value.
 */
trait ResolvesEnvironment
{
    protected function environments(): EnvironmentContext
    {
        return app(EnvironmentContext::class);
    }
}
