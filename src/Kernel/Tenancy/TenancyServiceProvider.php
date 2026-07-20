<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;

/**
 * Registers the tenancy kernel. The context managers are `scoped`, not
 * `singleton`: the current tenant/environment (and its suspension counter) is
 * stable for one request or queued job, but is reset between them. Under a
 * long-lived runtime (Octane/RoadRunner) this is load-bearing — a worker killed
 * inside a `withoutScope()` block must not carry a leaked suspension into the
 * next request, which would collapse deny-by-default scoping platform-wide.
 */
class TenancyServiceProvider extends ServiceProvider implements DeferrableProvider
{
    public function register(): void
    {
        $this->app->scoped(TenantContext::class, TenantContextManager::class);
        $this->app->scoped(EnvironmentContext::class, EnvironmentContextManager::class);
    }

    /**
     * @return array<int, class-string>
     */
    public function provides(): array
    {
        return [TenantContext::class, EnvironmentContext::class];
    }
}
