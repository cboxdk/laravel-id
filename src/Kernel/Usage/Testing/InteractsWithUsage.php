<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Testing;

use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;

trait InteractsWithUsage
{
    protected function fakeUsage(): FakeUsageMeter
    {
        $fake = new FakeUsageMeter;
        app()->instance(UsageMeter::class, $fake);

        return $fake;
    }
}
