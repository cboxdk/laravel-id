<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Provisioning\Testing\InteractsWithProvisioning;

/**
 * Composition site so the shippable InteractsWithProvisioning trait is type-checked.
 */
final class ProvisioningHarness
{
    use InteractsWithProvisioning;
}
