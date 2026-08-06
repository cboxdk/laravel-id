<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Usage\Testing\InteractsWithUsage;

/**
 * Composition site so the shippable InteractsWithUsage trait is type-checked.
 */
final class UsageHarness
{
    use InteractsWithUsage;
}
