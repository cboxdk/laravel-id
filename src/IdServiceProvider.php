<?php

declare(strict_types=1);

namespace Cbox\Id;

use Cbox\Id\Kernel\Tenancy\TenancyServiceProvider;
use Illuminate\Support\ServiceProvider;

/**
 * Root service provider for the Cbox ID platform.
 *
 * Each module registers its bindings via a dedicated module provider, wired up
 * here in dependency order (kernels first).
 */
final class IdServiceProvider extends ServiceProvider
{
    /**
     * Module providers, in dependency order (kernels before domain modules).
     *
     * @var array<int, class-string<ServiceProvider>>
     */
    private const MODULE_PROVIDERS = [
        TenancyServiceProvider::class,
    ];

    public function register(): void
    {
        foreach (self::MODULE_PROVIDERS as $provider) {
            $this->app->register($provider);
        }
    }

    public function boot(): void
    {
        //
    }
}
