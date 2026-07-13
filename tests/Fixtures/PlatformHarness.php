<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Platform\Testing\InteractsWithPlatform;

/**
 * Composition site so the shippable InteractsWithPlatform trait is type-checked.
 */
final class PlatformHarness
{
    use InteractsWithPlatform;
}
