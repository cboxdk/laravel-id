<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Listeners;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Enums\UsageMetric;
use Cbox\Id\Kernel\Usage\EventMetricMap;
use Illuminate\Support\Facades\DB;

/**
 * Meters domain events off the transactional outbox: it maps a delivered event's
 * `type` to a {@see UsageMetric} (via {@see EventMetricMap}, the shared mapping) and
 * increments the counter, attributed to the event's organization. Decoupled from
 * every emit site — new metered events are a map entry.
 *
 * Delivery is at-least-once, and a raw increment is not idempotent, so each event is
 * metered exactly once: an `insertOrIgnore` into `usage_metered_events` keyed on the
 * event id is the guard — only the first delivery (the insert that took) records.
 */
final class RecordUsageOnDomainEvent
{
    public function __construct(private readonly UsageMeter $meter) {}

    public function handle(EventDelivered $delivered): void
    {
        $metric = EventMetricMap::for($delivered->event->type);

        if (! $metric instanceof UsageMetric) {
            return;
        }

        // Exactly-once under at-least-once delivery: only the first delivery whose
        // marker insert takes (affected = 1) proceeds to increment.
        $fresh = DB::table('usage_metered_events')->insertOrIgnore([
            'event_id' => $delivered->event->id,
            'created_at' => now(),
        ]);

        if ($fresh === 0) {
            return;
        }

        $this->meter->record($metric->value, 1, $delivered->event->organization_id);
    }
}
