<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Contracts\Events\Dispatcher;

final class DatabaseEventBus implements EventBus
{
    public function __construct(
        private readonly Dispatcher $dispatcher,
        private readonly EnvironmentContext $environments,
    ) {}

    public function emit(DomainEvent $event): Event
    {
        $row = new Event;
        $row->fill([
            'type' => $event->type,
            'organization_id' => $event->organizationId,
            // Stamp the ambient environment at emit — the relay flushes across
            // environments, so this is how a delivered event carries its origin
            // (the outbox row is deliberately NOT environment-scoped itself).
            'environment_id' => $this->environments->current()?->environmentKey(),
            'payload' => $event->payload,
            'occurred_at' => now(),
        ]);
        $row->save();

        return $row;
    }

    public function flushPending(int $limit = 100): int
    {
        $pending = Event::query()
            ->whereNull('dispatched_at')
            ->orderBy('occurred_at')
            ->limit($limit)
            ->get();

        foreach ($pending as $event) {
            $this->dispatcher->dispatch(new EventDelivered($event));
            $event->forceFill(['dispatched_at' => now()])->save();
        }

        return $pending->count();
    }
}
