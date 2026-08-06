<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\ValueObjects;

use Illuminate\Support\Carbon;

/**
 * A point-in-time reading of the domain-event outbox.
 *
 * `waiting` is what a relay pass would pick up right now (unclaimed, or claimed
 * by a relay that has since gone stale). `inFlight` is claimed and still within
 * the reclaim window — a healthy relay working. Depth alone is not enough to
 * alarm on: a large but MOVING backlog is fine, a small but AGEING one is not,
 * so the oldest undelivered event's age travels with the count.
 */
final readonly class BacklogDepth
{
    public function __construct(
        public int $waiting,
        public int $inFlight,
        public ?Carbon $oldestUndeliveredAt,
    ) {}

    public function total(): int
    {
        return $this->waiting + $this->inFlight;
    }

    /** Age of the oldest undelivered event, in seconds; 0 when the outbox is drained. */
    public function oldestAgeSeconds(): int
    {
        if ($this->oldestUndeliveredAt === null) {
            return 0;
        }

        // Carbon 3 returns a float; the reading is a whole-second gauge.
        return max(0, (int) $this->oldestUndeliveredAt->diffInSeconds(Carbon::now(), absolute: false));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'waiting' => $this->waiting,
            'in_flight' => $this->inFlight,
            'total' => $this->total(),
            'oldest_undelivered_at' => $this->oldestUndeliveredAt?->toIso8601String(),
            'oldest_age_seconds' => $this->oldestAgeSeconds(),
        ];
    }
}
