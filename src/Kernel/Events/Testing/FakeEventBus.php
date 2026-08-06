<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Events\Testing;

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Closure;
use PHPUnit\Framework\Assert;

/**
 * In-memory {@see EventBus} for tests: captures emitted events and exposes
 * assertions, in the spirit of Laravel's `Event::fake()`.
 */
class FakeEventBus implements EventBus
{
    /**
     * @var list<DomainEvent>
     */
    public array $emitted = [];

    public function emit(DomainEvent $event): Event
    {
        $this->emitted[] = $event;

        return (new Event)->fill([
            'type' => $event->type,
            'organization_id' => $event->organizationId,
            'payload' => $event->payload,
        ]);
    }

    public function flushPending(int $limit = 100): int
    {
        return 0;
    }

    /**
     * @param  (Closure(DomainEvent): bool)|null  $callback
     */
    public function assertEmitted(string $type, ?Closure $callback = null): void
    {
        $matches = array_filter(
            $this->emitted,
            fn (DomainEvent $event): bool => $event->type === $type
                && ($callback === null || $callback($event)),
        );

        Assert::assertNotEmpty($matches, "Expected event [{$type}] to be emitted, but it was not.");
    }

    public function assertNotEmitted(string $type): void
    {
        $matches = array_filter($this->emitted, fn (DomainEvent $event): bool => $event->type === $type);

        Assert::assertEmpty($matches, "Did not expect event [{$type}] to be emitted.");
    }

    public function assertNothingEmitted(): void
    {
        Assert::assertEmpty($this->emitted, 'Expected no events to be emitted.');
    }

    public function assertEmittedCount(int $count): void
    {
        Assert::assertCount($count, $this->emitted);
    }
}
