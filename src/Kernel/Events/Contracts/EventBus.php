<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Contracts;

use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;

/**
 * Transactional-outbox event bus.
 *
 * {@see emit()} persists the event in the caller's current database transaction,
 * so a committed state change always has its event and a rolled-back one never
 * does — no dual-write. Delivery is decoupled: the relay {@see flushPending()}
 * (driven by a scheduled command / worker) dispatches undelivered rows, so no
 * event is lost even if the process dies right after commit.
 */
interface EventBus
{
    public function emit(DomainEvent $event): Event;

    /**
     * Deliver up to `$limit` undelivered events (oldest first) and mark them
     * dispatched. Idempotent and safe to run repeatedly. Returns the count delivered.
     */
    public function flushPending(int $limit = 100): int;
}
