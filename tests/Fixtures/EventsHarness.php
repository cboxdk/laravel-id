<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Fixtures;

use Cbox\Id\Kernel\Events\Testing\InteractsWithEvents;

/**
 * Composition site so the shippable InteractsWithEvents trait is type-checked.
 */
final class EventsHarness
{
    use InteractsWithEvents;
}
