<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\ExternalActions\Testing\InteractsWithExternalActions;

/**
 * Composition site so the shippable InteractsWithExternalActions trait is type-checked.
 */
final class ExternalActionsHarness
{
    use InteractsWithExternalActions;
}
