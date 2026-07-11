<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;

final class FakeTenant implements Tenant
{
    public function __construct(private readonly string $key) {}

    public function tenantKey(): string
    {
        return $this->key;
    }
}
