<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Testing;

use Cbox\Id\Kernel\Events\Contracts\EventBus;

/**
 * Swap the event bus for an assertable fake:
 *
 *     $events = $this->fakeEvents();
 *     // ... exercise code ...
 *     $events->assertEmitted('organization.created');
 */
trait InteractsWithEvents
{
    protected function fakeEvents(): FakeEventBus
    {
        $fake = new FakeEventBus;

        app()->instance(EventBus::class, $fake);

        return $fake;
    }
}
