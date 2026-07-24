<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support;

use Cbox\Id\Tests\TestCase;

/**
 * Boots the platform with the bring-your-own-RBAC driver (`access_control.driver =
 * external`) selected before the service providers register, so the built-in RBAC
 * bindings and migrations are gated off exactly as they would be in a host app.
 *
 * The driver is set through the environment variable the config default reads,
 * before the application is created — a real app loads config before providers
 * register, but Testbench's defineEnvironment hook runs too late for the register()
 * phase, so the env var is what makes the register-time binding see the driver.
 */
abstract class ExternalDriverTestCase extends TestCase
{
    protected function setUp(): void
    {
        putenv('CBOX_ID_ACCESS_CONTROL_DRIVER=external');
        $_ENV['CBOX_ID_ACCESS_CONTROL_DRIVER'] = 'external';
        $_SERVER['CBOX_ID_ACCESS_CONTROL_DRIVER'] = 'external';

        parent::setUp();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        putenv('CBOX_ID_ACCESS_CONTROL_DRIVER');
        unset($_ENV['CBOX_ID_ACCESS_CONTROL_DRIVER'], $_SERVER['CBOX_ID_ACCESS_CONTROL_DRIVER']);
    }
}
