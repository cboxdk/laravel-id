<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Governance\Testing\InteractsWithGovernance;

/**
 * Composition site so the shippable InteractsWithGovernance trait is type-checked.
 */
final class GovernanceHarness
{
    use InteractsWithGovernance;
}
