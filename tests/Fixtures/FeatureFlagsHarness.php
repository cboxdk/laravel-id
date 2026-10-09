<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\FeatureFlags\Testing\InteractsWithFeatureFlags;

/**
 * Composition site so the shippable InteractsWithFeatureFlags trait is type-checked.
 */
final class FeatureFlagsHarness
{
    use InteractsWithFeatureFlags;
}
