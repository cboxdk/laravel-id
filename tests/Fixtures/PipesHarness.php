<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Pipes\Testing\InteractsWithPipes;

/**
 * Composition site so the shippable InteractsWithPipes trait is type-checked.
 */
final class PipesHarness
{
    use InteractsWithPipes;
}
