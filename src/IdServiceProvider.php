<?php

declare(strict_types=1);

namespace Cbox\Id;

use Cbox\Id\AccessControl\AccessControlServiceProvider;
use Cbox\Id\Api\ApiServiceProvider;
use Cbox\Id\AuditQuery\AuditQueryServiceProvider;
use Cbox\Id\AuditStreaming\AuditStreamingServiceProvider;
use Cbox\Id\Console\DirectorySyncCommand;
use Cbox\Id\Console\DoctorCommand;
use Cbox\Id\Console\HealthChecks;
use Cbox\Id\Console\ImportUsersCommand;
use Cbox\Id\Console\InstallCommand;
use Cbox\Id\Directory\DirectoryServiceProvider;
use Cbox\Id\ExternalActions\ExternalActionsServiceProvider;
use Cbox\Id\Federation\FederationServiceProvider;
use Cbox\Id\Governance\GovernanceServiceProvider;
use Cbox\Id\Identity\IdentityServiceProvider;
use Cbox\Id\Kernel\Audit\AuditServiceProvider;
use Cbox\Id\Kernel\Authorization\AuthorizationServiceProvider;
use Cbox\Id\Kernel\Crypto\CryptoServiceProvider;
use Cbox\Id\Kernel\Events\EventsServiceProvider;
use Cbox\Id\Kernel\Tenancy\TenancyServiceProvider;
use Cbox\Id\Kernel\Usage\UsageServiceProvider;
use Cbox\Id\Maintenance\MaintenanceServiceProvider;
use Cbox\Id\OAuthServer\OAuthServerServiceProvider;
use Cbox\Id\Organization\OrganizationServiceProvider;
use Cbox\Id\Otp\OtpServiceProvider;
use Cbox\Id\Platform\PlatformServiceProvider;
use Cbox\Id\Provisioning\ProvisioningServiceProvider;
use Cbox\Id\SamlIdp\SamlIdpServiceProvider;
use Cbox\Id\Support\PackageConfigMerger;
use Cbox\Id\TokenVault\TokenVaultServiceProvider;
use Cbox\Id\Webhooks\WebhookServiceProvider;
use Illuminate\Support\ServiceProvider;

/**
 * Root service provider for the Cbox ID platform.
 *
 * Each module registers its bindings via a dedicated module provider, wired up
 * here in dependency order (kernels first).
 */
class IdServiceProvider extends ServiceProvider
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
        UsageServiceProvider::class,
        // Domain modules
        OrganizationServiceProvider::class,
        PlatformServiceProvider::class,
        IdentityServiceProvider::class,
        // Delivered-OTP (email/SMS) verification + MFA factor. After Identity so it
        // sits alongside the other authentication factors; depends only on kernels.
        OtpServiceProvider::class,
        AccessControlServiceProvider::class,
        // Access governance (IGA): certification campaigns + Segregation of Duties.
        // After AccessControl and Organization, whose role/membership grants it
        // enumerates, certifies and revokes.
        GovernanceServiceProvider::class,
        AuditQueryServiceProvider::class,
        DirectoryServiceProvider::class,
        FederationServiceProvider::class,
        // Inline hooks / external actions: synchronous extension points that can
        // enrich or veto an operation. Registered before OAuthServer because the
        // token issuer runs the TokenMinting hook; depends only on kernels + the SSRF
        // guard.
        ExternalActionsServiceProvider::class,
        OAuthServerServiceProvider::class,
        // AI token vault: seals downstream third-party credentials and brokers
        // deny-by-default leased access to agent (OAuth client) principals.
        // Depends only on kernels (Crypto/Audit/Tenancy); placed alongside the
        // OAuth/agent machinery it serves.
        TokenVaultServiceProvider::class,
        SamlIdpServiceProvider::class,
        WebhookServiceProvider::class,
        // Outbound SCIM 2.0 provisioning: the mirror of the Directory (inbound
        // SCIM server) module — pushes user/membership changes OUT to downstream
        // apps. Registered after the domain modules whose events it subscribes to.
        ProvisioningServiceProvider::class,
        // Registered after AuditServiceProvider so the base AuditLog binding
        // exists to decorate; composes cboxdk/laravel-siem for env-isolated SIEM
        // audit streaming.
        AuditStreamingServiceProvider::class,
        // Data-lifecycle sweep (`cbox-id:prune`). Last of the domain modules: it
        // names tables owned by Identity, OAuthServer, Webhooks and Provisioning, so
        // it registers once those modules' enums and schema are in place.
        MaintenanceServiceProvider::class,
        ApiServiceProvider::class,
    ];

    public function register(): void
    {
        // The registry a host fills with checks `cbox-id:doctor` should also run. A
        // singleton because a service provider populates it at boot and the command
        // reads it later, in the same process.
        $this->app->singleton(HealthChecks::class);

        // Merge package defaults so config('cbox-id.*') resolves in a host app
        // even before the config is published.
        //
        // NOT `mergeConfigFrom()`: that helper is a single `array_merge`, so a host
        // that publishes a PARTIAL `config/cbox-id.php` — naming one key under
        // `oauth`, say — replaces the package's entire `oauth` block and deletes
        // every default it did not restate. The deleted defaults are all env-backed,
        // so the visible symptom is an operator setting `CBOX_ID_ACCESS_TOKEN_TTL`
        // and nothing happening. PackageConfigMerger fills in only what the host is
        // silent about; see the rules documented on that class.
        PackageConfigMerger::mergeInto($this->app, __DIR__.'/../config/cbox-id.php', 'cbox-id');

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
            $this->commands([InstallCommand::class, DoctorCommand::class, ImportUsersCommand::class, DirectorySyncCommand::class]);

            $this->publishes([
                __DIR__.'/../config/cbox-id.php' => config_path('cbox-id.php'),
            ], 'cbox-id-config');

            // Publish every migration FLAT into the host's migrations directory —
            // including the builtin-RBAC set that lives in the access-control/ subdir
            // (kept out of the top level so the non-recursive auto-loader can gate it
            // on access_control.driver). A host's own migrator is likewise
            // non-recursive, so a nested copy would silently never run.
            $migrationPublishMap = [];
            foreach ([
                __DIR__.'/../database/migrations/*_*.php',
                __DIR__.'/../database/migrations/access-control/*_*.php',
            ] as $pattern) {
                foreach (glob($pattern) ?: [] as $migration) {
                    $migrationPublishMap[$migration] = database_path('migrations/'.basename($migration));
                }
            }
            $this->publishes($migrationPublishMap, 'cbox-id-migrations');

            // Optional: the canonical users table for greenfield installs only.
            // Apps with existing users never publish this.
            $this->publishes([
                __DIR__.'/../database/publishable/2026_01_01_000000_create_cbox_id_users_table.php' => database_path('migrations/2026_01_01_000000_create_cbox_id_users_table.php'),
            ], 'cbox-id-users-migration');
        }
    }
}
