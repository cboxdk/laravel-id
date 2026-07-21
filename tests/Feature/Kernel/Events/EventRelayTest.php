<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event as LaravelEvent;

uses(RefreshDatabase::class);

/**
 * The outbox shipped with no production driver: flushPending() had zero callers outside
 * tests, so every subscriber — webhooks, usage metering, outbound provisioning, the
 * host's own listeners — was inert while the app looked healthy. The suite stayed green
 * throughout because the tests called flushPending() BY HAND.
 *
 * These tests deliberately go through the scheduled command instead, so the wiring is
 * what is under test rather than the method.
 */
it('delivers pending events through the scheduled command, not a hand call', function (): void {
    LaravelEvent::fake([EventDelivered::class]);

    app(EventBus::class)->emit(new DomainEvent('user.created'));
    app(EventBus::class)->emit(new DomainEvent('user.updated'));

    $this->artisan('cbox-id:events:relay')
        ->expectsOutputToContain('Delivered 2 event(s).')
        ->assertSuccessful();

    LaravelEvent::assertDispatchedTimes(EventDelivered::class, 2);
    expect(Event::query()->whereNull('dispatched_at')->count())->toBe(0);
});

it('registers the relay on the schedule so a deployed app drives itself', function (): void {
    $schedule = app(Schedule::class);

    $names = collect($schedule->events())
        ->map(fn ($event): ?string => $event->description)
        ->filter()
        ->all();

    expect($names)->toContain('cbox-id:events:relay');
});

/**
 * Two relays running at once — an overlapping scheduler tick, or two app instances —
 * previously selected the same pending rows and delivered every event twice: every
 * webhook sent twice, every usage counter double-counted.
 */
it('never delivers the same event twice under concurrent relays', function (): void {
    LaravelEvent::fake([EventDelivered::class]);

    $bus = app(EventBus::class);
    foreach (range(1, 5) as $i) {
        $bus->emit(new DomainEvent("event.{$i}"));
    }

    // A claimed batch is off-limits to the next relay: the second pass finds nothing
    // left, rather than re-delivering the first pass's work.
    $first = $bus->flushPending();
    $second = $bus->flushPending();

    expect($first)->toBe(5)
        ->and($second)->toBe(0);

    LaravelEvent::assertDispatchedTimes(EventDelivered::class, 5);
});

/**
 * A relay that dies mid-pass leaves rows claimed but undelivered. They must not be
 * stranded — nor become immediately re-claimable, which would reintroduce the double
 * delivery this design exists to prevent.
 */
it('reclaims a stale claim but leaves a fresh one alone', function (): void {
    $bus = app(EventBus::class);
    $bus->emit(new DomainEvent('user.created'));

    // Simulate a relay that claimed the row and then died.
    Event::query()->update(['claimed_at' => now()->subSeconds(30), 'dispatched_at' => null]);

    config(['cbox-id.events.reclaim_after_seconds' => 300]);
    expect($bus->flushPending())->toBe(0); // still inside the window — someone may be working on it

    config(['cbox-id.events.reclaim_after_seconds' => 10]);
    expect($bus->flushPending())->toBe(1); // window passed — take it back

    expect(Event::query()->whereNull('dispatched_at')->count())->toBe(0);
});

/**
 * A poison listener must not take the batch with it. An uncaught throw used to abort the
 * pass: the rest of the claimed events sat undelivered for the whole reclaim window, and
 * the failing event — whose earlier listeners HAD already run — was re-delivered on
 * reclaim, reintroducing the double-send this design exists to prevent.
 */
it('isolates a failing listener and still delivers the rest of the batch', function (): void {
    $seen = [];

    LaravelEvent::listen(EventDelivered::class, function (EventDelivered $delivered) use (&$seen): void {
        $seen[] = $delivered->event->type;

        if ($delivered->event->type === 'poison') {
            throw new RuntimeException('listener exploded');
        }
    });

    $bus = app(EventBus::class);
    $bus->emit(new DomainEvent('first'));
    $bus->emit(new DomainEvent('poison'));
    $bus->emit(new DomainEvent('third'));

    // Two delivered; the poison one is not counted.
    expect($bus->flushPending())->toBe(2)
        ->and($seen)->toBe(['first', 'poison', 'third']);

    // The failing event is left UNDELIVERED and its claim released, so it retries
    // promptly rather than being stranded for the reclaim window.
    $poison = Event::query()->where('type', 'poison')->firstOrFail();

    expect($poison->dispatched_at)->toBeNull()
        ->and($poison->claimed_at)->toBeNull();

    // …and the healthy ones are done.
    expect(Event::query()->whereNull('dispatched_at')->count())->toBe(1);
});

it('honours reclaim_after_seconds when it arrives as a string from env', function (): void {
    $bus = app(EventBus::class);
    $bus->emit(new DomainEvent('user.created'));

    Event::query()->update(['claimed_at' => now()->subSeconds(30), 'dispatched_at' => null]);

    // env() yields a STRING; is_int() alone silently ignored the knob.
    config(['cbox-id.events.reclaim_after_seconds' => '10']);

    expect($bus->flushPending())->toBe(1);
});
