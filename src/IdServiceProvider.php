<?php

declare(strict_types=1);

namespace Cbox\Id;

use Cbox\Id\AccessControl\AccessControlServiceProvider;
use Cbox\Id\Api\ApiServiceProvider;
use Cbox\Id\AuditQuery\AuditQueryServiceProvider;
use Cbox\Id\Directory\DirectoryServiceProvider;
use Cbox\Id\Federation\FederationServiceProvider;
use Cbox\Id\Identity\IdentityServiceProvider;
use Cbox\Id\Kernel\Audit\AuditServiceProvider;
use Cbox\Id\Kernel\Authorization\AuthorizationServiceProvider;
use Cbox\Id\Kernel\Crypto\CryptoServiceProvider;
use Cbox\Id\Kernel\Events\EventsServiceProvider;
use Cbox\Id\Kernel\Tenancy\TenancyServiceProvider;
use Cbox\Id\OAuthServer\OAuthServerServiceProvider;
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
        AuditQueryServiceProvider::class,
        DirectoryServiceProvider::class,
        FederationServiceProvider::class,
        OAuthServerServiceProvider::class,
        WebhookServiceProvider::class,
        ApiServiceProvider::class,
    ];

    public function register(): void
    {
        // Merge package defaults so config('cbox-id.*') resolves in a host app
        // even before the config is published.
        $this->mergeConfigFrom(__DIR__.'/../config/cbox-id.php', 'cbox-id');

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
                __DIR__.'/../config/cbox-id.php' => config_path('cbox-id.php'),
            ], 'cbox-id-config');

            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'cbox-id-migrations');

            // Optional: the canonical users table for greenfield installs only.
            // Apps with existing users never publish this.
            $this->publishes([
                __DIR__.'/../database/publishable/2026_01_01_000000_create_cbox_id_users_table.php' => database_path('migrations/2026_01_01_000000_create_cbox_id_users_table.php'),
            ], 'cbox-id-users-migration');
        }
    }
}
