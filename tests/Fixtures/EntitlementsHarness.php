<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Authorization\Testing\InteractsWithEntitlements;

/**
 * Composition site so the shippable InteractsWithEntitlements trait is type-checked.
 */
final class EntitlementsHarness
{
    use InteractsWithEntitlements;
}
