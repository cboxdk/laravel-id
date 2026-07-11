<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy;

use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;

/**
 * Registers the tenancy kernel. The {@see TenantContext} is a singleton so the
 * current tenant is stable for the lifetime of a request or queued job.
 */
final class TenancyServiceProvider extends ServiceProvider implements DeferrableProvider
{
    public function register(): void
    {
        $this->app->singleton(TenantContext::class, TenantContextManager::class);
    }

    /**
     * @return array<int, class-string>
     */
    public function provides(): array
    {
        return [TenantContext::class];
    }
}
