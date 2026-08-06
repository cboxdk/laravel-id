<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\SamlIdp\Testing\InteractsWithSamlIdp;

/**
 * Composition site so the shippable InteractsWithSamlIdp trait is type-checked.
 */
final class SamlIdpHarness
{
    use InteractsWithSamlIdp;
}
