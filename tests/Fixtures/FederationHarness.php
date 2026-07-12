<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Federation\Testing\InteractsWithFederation;

/**
 * Composition site so the shippable InteractsWithFederation trait is type-checked.
 */
final class FederationHarness
{
    use InteractsWithFederation;
}
