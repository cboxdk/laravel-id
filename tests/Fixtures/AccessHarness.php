<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Organization\Testing\InteractsWithAccess;

/**
 * Composition site so the shippable InteractsWithAccess trait is type-checked.
 */
final class AccessHarness
{
    use InteractsWithAccess;
}
