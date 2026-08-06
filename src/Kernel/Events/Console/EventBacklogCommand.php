<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Console;

use Cbox\Id\Kernel\Events\Contracts\RelayBacklog;
use Illuminate\Console\Command;

/**
 * Report how far behind the domain-event relay is.
 *
 * This is the host-facing form of the backlog signal: `laravel-id` is a
 * dependency-light framework package and deliberately does not depend on a
 * telemetry runtime, so instead of pushing a gauge it exposes the depth here
 * (and via {@see RelayBacklog} for a host that HAS metrics wiring).
 *
 * `--fail-over` makes it usable as a health check straight from cron/Kubernetes:
 * a non-zero exit when the waiting depth crosses the given number.
 */
class EventBacklogCommand extends Command
{
    protected $signature = 'cbox-id:events:backlog
        {--json : Emit the reading as JSON}
        {--fail-over= : Exit non-zero when the waiting depth is at or above this number}';

    protected $description = 'Report the domain-event outbox backlog (relay lag).';

    public function handle(RelayBacklog $backlog): int
    {
        $depth = $backlog->depth();

        if ($this->option('json') === true) {
            $this->line((string) json_encode($depth->toArray(), JSON_THROW_ON_ERROR));
        } else {
            $this->table(['Metric', 'Value'], [
                ['waiting', (string) $depth->waiting],
                ['in flight', (string) $depth->inFlight],
                ['total', (string) $depth->total()],
                ['oldest undelivered', $depth->oldestUndeliveredAt?->toIso8601String() ?? '—'],
                ['oldest age (s)', (string) $depth->oldestAgeSeconds()],
            ]);
        }

        $failOver = $this->option('fail-over');

        if (is_string($failOver) && is_numeric($failOver) && $depth->waiting >= (int) $failOver) {
            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
