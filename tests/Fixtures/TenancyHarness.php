<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;

/**
 * Composition site that type-checks the shippable InteractsWithTenancy trait
 * under static analysis. Real test cases compose it exactly the same way.
 */
final class TenancyHarness
{
    use InteractsWithTenancy;
}
