<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\AccessControl\Testing\InteractsWithAccessControl;

/**
 * Composition site so the shippable InteractsWithAccessControl trait is type-checked.
 */
final class AccessControlHarness
{
    use InteractsWithAccessControl;
}
