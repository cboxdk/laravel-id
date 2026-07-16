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
use Cbox\Id\Licensing\Testing\InteractsWithLicensing;
use Cbox\Id\OAuthServer\Testing\InteractsWithOAuth;
use Cbox\Id\Organization\Testing\InteractsWithOrganizations;
use Cbox\Id\Otp\Testing\InteractsWithOtp;
use Cbox\Id\Provisioning\Testing\InteractsWithProvisioning;
use Cbox\Id\SamlIdp\Testing\InteractsWithSamlIdp;
use Cbox\Id\TokenVault\Testing\InteractsWithTokenVault;
use Cbox\Id\Webhooks\Testing\InteractsWithWebhooks;
use Cbox\Ssrf\SsrfServiceProvider;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
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
    use InteractsWithLicensing;
    use InteractsWithOAuth;
    use InteractsWithOrganizations;
    use InteractsWithOtp;
    use InteractsWithProvisioning;
    use InteractsWithSamlIdp;
    use InteractsWithTenancy;
    use InteractsWithTokenVault;
    use InteractsWithWebhooks;

    protected function setUp(): void
    {
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
        $this->loadMigrationsFrom(dirname(__DIR__).'/database/publishable');
    }

    protected function defineEnvironment($app): void
    {
        /** @var Application $app */
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]);

        // A throwaway crypto master key for the test run.
        $app['config']->set('cbox-id.environments.default', 'env_test');

        $app['config']->set('cbox-id.crypto.key', base64_encode(random_bytes(32)));

        // App key for the encryption/session stack (web middleware, e.g. the OIDC
        // redirect flow, needs it).
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
    }
}
