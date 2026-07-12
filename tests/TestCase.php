<?php

declare(strict_types=1);

namespace Cbox\Id\Tests;

use Cbox\Id\AccessControl\Testing\InteractsWithAccessControl;
use Cbox\Id\Directory\Testing\InteractsWithDirectory;
use Cbox\Id\Identity\Testing\InteractsWithIdentity;
use Cbox\Id\IdServiceProvider;
use Cbox\Id\Kernel\Audit\Testing\InteractsWithAudit;
use Cbox\Id\Kernel\Authorization\Testing\InteractsWithAuthorization;
use Cbox\Id\Kernel\Authorization\Testing\InteractsWithEntitlements;
use Cbox\Id\Kernel\Events\Testing\InteractsWithEvents;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Testing\InteractsWithOrganizations;
use Cbox\Id\Webhooks\Testing\InteractsWithWebhooks;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use InteractsWithAccessControl;
    use InteractsWithAudit;
    use InteractsWithAuthorization;
    use InteractsWithDirectory;
    use InteractsWithEntitlements;
    use InteractsWithEvents;
    use InteractsWithIdentity;
    use InteractsWithOrganizations;
    use InteractsWithTenancy;
    use InteractsWithWebhooks;

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [IdServiceProvider::class];
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
        $app['config']->set('cbox-id.crypto.key', base64_encode(random_bytes(32)));
    }
}
