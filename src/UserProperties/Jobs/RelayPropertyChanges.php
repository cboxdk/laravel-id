<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Jobs;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;

/** Wake the durable outbox after commit; its scheduled relay remains the recovery path. */
class RelayPropertyChanges implements ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(EventBus $events): void
    {
        // The bus restores each event's environment itself, including on a fresh worker.
        $events->flushPending(100);
    }
}
