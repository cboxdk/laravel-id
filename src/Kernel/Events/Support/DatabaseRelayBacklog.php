<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Support;

use Cbox\Id\Kernel\Events\Contracts\RelayBacklog;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\BacklogDepth;
use Illuminate\Support\Carbon;

/**
 * Reads the outbox depth straight off the `events` table.
 *
 * The outbox row is deliberately NOT environment-owned, so this counts across
 * every environment — which is exactly right for a relay signal: the relay is a
 * single cross-environment process, and its lag is a platform-level fact.
 */
class DatabaseRelayBacklog implements RelayBacklog
{
    public function depth(): BacklogDepth
    {
        // Same window the relay's claim() uses: a claim older than this belongs to
        // a relay that died mid-pass, so those rows are waiting, not in flight.
        $staleBefore = Carbon::now()->subSeconds($this->reclaimAfterSeconds());

        // Dead-lettered rows are excluded from every count here: the relay will never
        // claim them again, so counting them as backlog would make a rising gauge that
        // no amount of relay capacity could ever bring down — and would hide a REAL
        // backlog behind a permanent floor. They are an operator's queue, not the relay's.
        $waiting = Event::query()
            ->whereNull('dispatched_at')
            ->whereNull('dead_lettered_at')
            ->where(fn ($query) => $query->whereNull('claimed_at')->orWhere('claimed_at', '<', $staleBefore))
            ->count();

        $inFlight = Event::query()
            ->whereNull('dispatched_at')
            ->whereNull('dead_lettered_at')
            ->whereNotNull('claimed_at')
            ->where('claimed_at', '>=', $staleBefore)
            ->count();

        $oldest = Event::query()
            ->whereNull('dispatched_at')
            ->whereNull('dead_lettered_at')
            ->min('occurred_at');

        return new BacklogDepth(
            waiting: $waiting,
            inFlight: $inFlight,
            oldestUndeliveredAt: is_string($oldest) ? Carbon::parse($oldest) : null,
        );
    }

    private function reclaimAfterSeconds(): int
    {
        $configured = config('cbox-id.events.reclaim_after_seconds', 300);

        return is_numeric($configured) && (int) $configured > 0 ? (int) $configured : 300;
    }
}
