<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Console;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Illuminate\Console\Command;

/**
 * Drive the domain-event outbox.
 *
 * Emitting a domain event only writes a row; nothing is delivered until this runs.
 * Every downstream subscriber hangs off it — webhook fan-out, usage metering, outbound
 * SCIM provisioning, group→role reconciliation, and the host's own listeners — so if
 * this is not scheduled, all of them are silently inert while the app looks healthy.
 */
class RelayEventsCommand extends Command
{
    protected $signature = 'cbox-id:events:relay {--limit=100 : Events to deliver in one pass}';

    protected $description = 'Deliver pending domain events from the outbox.';

    public function handle(EventBus $events): int
    {
        $limit = (int) $this->option('limit');

        if ($limit < 1) {
            $this->error('The --limit must be at least 1.');

            return self::FAILURE;
        }

        $delivered = $events->flushPending($limit);

        $this->info(sprintf('Delivered %d event(s).', $delivered));

        return self::SUCCESS;
    }
}
