<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Licensing\Testing\InteractsWithLicensing;

/**
 * Composition site so the shippable InteractsWithLicensing trait is type-checked.
 */
final class LicensingHarness
{
    use InteractsWithLicensing;
}
