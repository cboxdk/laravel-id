<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Directory\Testing\InteractsWithDirectory;

/**
 * Composition site so the shippable InteractsWithDirectory trait is type-checked.
 */
final class DirectoryHarness
{
    use InteractsWithDirectory;
}
