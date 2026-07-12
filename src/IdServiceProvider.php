<?php

declare(strict_types=1);

namespace Cbox\Id;

use Cbox\Id\AccessControl\AccessControlServiceProvider;
use Cbox\Id\Identity\IdentityServiceProvider;
use Cbox\Id\Kernel\Audit\AuditServiceProvider;
use Cbox\Id\Kernel\Authorization\AuthorizationServiceProvider;
use Cbox\Id\Kernel\Crypto\CryptoServiceProvider;
use Cbox\Id\Kernel\Events\EventsServiceProvider;
use Cbox\Id\Kernel\Tenancy\TenancyServiceProvider;
use Cbox\Id\Organization\OrganizationServiceProvider;
use Cbox\Id\Webhooks\WebhookServiceProvider;
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
        CryptoServiceProvider::class,
        EventsServiceProvider::class,
        AuditServiceProvider::class,
        AuthorizationServiceProvider::class,
        // Domain modules
        OrganizationServiceProvider::class,
        IdentityServiceProvider::class,
        AccessControlServiceProvider::class,
        WebhookServiceProvider::class,
    ];

    public function register(): void
    {
        foreach (self::MODULE_PROVIDERS as $provider) {
            $this->app->register($provider);
        }
    }

    public function boot(): void
    {
        // Single source for all package migrations (module providers must not
        // each load the shared directory, or files would run twice).
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'cbox-id-migrations');
        }
    }
}
