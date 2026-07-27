<?php

declare(strict_types=1);

namespace Cbox\Id\Tests;

use Cbox\Id\AccessControl\Testing\InteractsWithAccessControl;
use Cbox\Id\AuditStreaming\Testing\InteractsWithAuditStreaming;
use Cbox\Id\Directory\Testing\InteractsWithDirectory;
use Cbox\Id\ExternalActions\Testing\InteractsWithExternalActions;
use Cbox\Id\Federation\Testing\InteractsWithFederation;
use Cbox\Id\Governance\Testing\InteractsWithGovernance;
use Cbox\Id\Identity\Testing\InteractsWithIdentity;
use Cbox\Id\Identity\Testing\InteractsWithImport;
use Cbox\Id\IdServiceProvider;
use Cbox\Id\Kernel\Audit\Testing\InteractsWithAudit;
use Cbox\Id\Kernel\Authorization\Testing\InteractsWithAuthorization;
use Cbox\Id\Kernel\Authorization\Testing\InteractsWithEntitlements;
use Cbox\Id\Kernel\Events\Testing\InteractsWithEvents;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Testing\InteractsWithOAuth;
use Cbox\Id\Organization\Testing\InteractsWithAccess;
use Cbox\Id\Organization\Testing\InteractsWithOrganizations;
use Cbox\Id\Otp\Testing\InteractsWithOtp;
use Cbox\Id\Provisioning\Testing\InteractsWithProvisioning;
use Cbox\Id\SamlIdp\Testing\InteractsWithSamlIdp;
use Cbox\Id\TokenVault\Testing\InteractsWithTokenVault;
use Cbox\Id\Webhooks\Testing\InteractsWithWebhooks;
use Cbox\Ssrf\SsrfServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\Attributes\ResetRefreshDatabaseState;
use Orchestra\Testbench\TestCase as Orchestra;

use function Orchestra\Testbench\load_migration_paths;

abstract class TestCase extends Orchestra
{
    use InteractsWithAccess;
    use InteractsWithAccessControl;
    use InteractsWithAudit;
    use InteractsWithAuditStreaming;
    use InteractsWithAuthorization;
    use InteractsWithDirectory;
    use InteractsWithEntitlements;
    use InteractsWithEvents;
    use InteractsWithExternalActions;
    use InteractsWithFederation;
    use InteractsWithGovernance;
    use InteractsWithIdentity;
    use InteractsWithImport;
    use InteractsWithOAuth;
    use InteractsWithOrganizations;
    use InteractsWithOtp;
    use InteractsWithProvisioning;
    use InteractsWithSamlIdp;
    use InteractsWithTenancy;
    use InteractsWithTokenVault;
    use InteractsWithWebhooks;

    /**
     * The access-control driver the currently migrated schema was built under.
     *
     * Only meaningful on the RefreshDatabase path, where ONE schema is shared by the
     * whole process — see below.
     */
    private static ?string $migratedUnderAccessControlDriver = null;

    protected function setUp(): void
    {
        // The built-in RBAC tables are registered by AccessControlServiceProvider only
        // when `access_control.driver` is `builtin` — that gating is the whole point of
        // the bring-your-own-RBAC tests in tests/External, which flip the driver to
        // `external` before the providers register.
        //
        // Under RefreshDatabase that gating turns into a trap: the FIRST test in the
        // process migrates, and every later test reuses that schema. Pest walks
        // External/ before Feature/, so the one migration ran with the built-in path
        // switched off and the entire Feature suite then queried `roles` and
        // `permissions` tables that were never created. Re-migrate when the driver
        // changes — twice per run, at the two boundaries, not per test.
        $driver = getenv('CBOX_ID_ACCESS_CONTROL_DRIVER') ?: 'builtin';

        if (static::usesRefreshDatabaseTestingConcern()
            && self::$migratedUnderAccessControlDriver !== null
            && self::$migratedUnderAccessControlDriver !== $driver) {
            ResetRefreshDatabaseState::run();
        }

        self::$migratedUnderAccessControlDriver = $driver;

        parent::setUp();

        // Every test runs inside a default environment — the hard outer scope is
        // deny-by-default, so without this the environment-owned models would
        // return nothing. Isolation tests override it with actingAsEnvironment().
        $this->actingAsEnvironment('env_test');
    }

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        // The SSRF guard package auto-registers via Laravel discovery in a real
        // app; Testbench needs it named explicitly.
        return [SsrfServiceProvider::class, IdServiceProvider::class];
    }

    /**
     * The platform does not auto-create a `users` table (it integrates with the
     * host's). Its own suite is a greenfield host, so it loads the optional
     * users migration — exactly what a greenfield app publishes.
     */
    protected function defineDatabaseMigrations(): void
    {
        $path = dirname(__DIR__).'/database/publishable';

        // Under RefreshDatabase (the server-engine path — see tests/Pest.php),
        // REGISTER the path with the migrator instead of migrating it here.
        //
        // `TestCase::loadMigrationsFrom()` only takes that shortcut itself while
        // RefreshDatabaseState::$migrated is false, i.e. for the very first test.
        // From the second on it spins up a MigrateProcessor — and Testbench's
        // teardown then calls ResetRefreshDatabaseState::run() for any test that
        // has both a cached processor AND the RefreshDatabase concern. That flips
        // $migrated back to false, so the NEXT test does a full `migrate:fresh`,
        // which caches another processor, which resets the state again. The
        // "migrate once" optimisation never engages: measured on MySQL 8.4 the
        // whole schema was being dropped and rebuilt for every single test, over a
        // minute a test, which is what made a server-engine CI job look impossible.
        if (static::usesRefreshDatabaseTestingConcern()) {
            load_migration_paths($this->app, $path);

            return;
        }

        $this->loadMigrationsFrom($path);
    }

    protected function defineEnvironment($app): void
    {
        /** @var Application $app */
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', $this->databaseConnection());

        // A throwaway crypto master key for the test run.
        $app['config']->set('cbox-id.environments.default', 'env_test');

        $app['config']->set('cbox-id.crypto.key', base64_encode(random_bytes(32)));

        // App key for the encryption/session stack (web middleware, e.g. the OIDC
        // redirect flow, needs it).
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    }

    /**
     * The suite runs on in-memory sqlite by default — fast, and hermetic per test.
     *
     * Sqlite cannot express row-level locking or two writers in the same database at
     * once, so anything that depends on real concurrency (the audit chain's append
     * serialisation) has to be exercised against a server engine. Setting
     * DB_CONNECTION to `pgsql`, `mysql` or `mariadb` plus the usual DB_* variables
     * points the whole suite at one, which is how the concurrency tests get a real
     * engine to contend on — and what the `engines` CI job runs. On those drivers
     * tests/Pest.php also switches the suite to RefreshDatabase; see the note there
     * for why re-migrating around every test is not an option on a server.
     *
     * (Named away from a `test` prefix on purpose — Pint's php_unit_method_casing
     * rule treats any such method in a test class as a test case and renames it.)
     *
     * @return array<string, mixed>
     */
    protected function databaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION');

        if (in_array($driver, ['pgsql', 'mysql', 'mariadb'], true)) {
            return [
                'driver' => $driver,
                'host' => getenv('DB_HOST') ?: '127.0.0.1',
                'port' => getenv('DB_PORT') ?: ($driver === 'pgsql' ? '5432' : '3306'),
                'database' => getenv('DB_DATABASE') ?: 'laravel_id',
                'username' => getenv('DB_USERNAME') ?: 'laravel',
                'password' => getenv('DB_PASSWORD') ?: '',
                'charset' => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
                'prefix' => '',
                'search_path' => 'public',
                'sslmode' => 'prefer',
            ];
        }

        return [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ];
    }
}
