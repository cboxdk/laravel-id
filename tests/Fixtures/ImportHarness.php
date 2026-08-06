<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Identity\Testing\InteractsWithImport;

/**
 * Composition site so the shippable InteractsWithImport trait is type-checked.
 */
final class ImportHarness
{
    use InteractsWithImport;
}
