<?php

declare(strict_types=1);

namespace Cbox\Id\Tests;

use Cbox\Id\IdServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [IdServiceProvider::class];
    }
}
