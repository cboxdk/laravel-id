<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Authorization\Testing\InteractsWithFineGrainedAuthorization;

/**
 * Composition site so the shippable InteractsWithFineGrainedAuthorization trait is type-checked.
 */
final class FineGrainedAuthorizationHarness
{
    use InteractsWithFineGrainedAuthorization;
}
