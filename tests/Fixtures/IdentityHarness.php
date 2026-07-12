<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Identity\Testing\InteractsWithIdentity;

/**
 * Composition site so the shippable InteractsWithIdentity trait is type-checked.
 */
final class IdentityHarness
{
    use InteractsWithIdentity;
}
