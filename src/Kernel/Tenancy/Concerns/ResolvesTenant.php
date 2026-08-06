<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Concerns;

use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;

/**
 * Resolve the ambient tenant LAZILY, per call — never capture it.
 *
 * The {@see ResolvesEnvironment} rule, for the other scoped context. `TenantContext` is
 * bound with `scoped()`, so a `singleton` that constructor-injects it holds ONE manager
 * for the life of the process; a queue worker's `forgetScopedInstances()` unsets the
 * binding without resetting that object, and job B then runs under job A's tenant.
 *
 * `runAs()` is not an exception to this — arguably it is the worst case. It sets the
 * tenant, runs a closure, and restores the previous value ON THE MANAGER IT WAS CALLED
 * ON. Called on a captured manager, both the set and the restore land on an object the
 * rest of the request is no longer reading, so the scoping silently does nothing.
 *
 * Enforced by `tests/Feature/Kernel/Tenancy/ScopedContextCaptureTest.php`.
 */
trait ResolvesTenant
{
    protected function tenant(): TenantContext
    {
        return app(TenantContext::class);
    }
}
