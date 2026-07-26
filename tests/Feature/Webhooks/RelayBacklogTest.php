<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\Contracts\RelayBacklog;
use Cbox\Id\Kernel\Events\Enums\RelayCadence;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('reports the outbox depth so relay lag is not silent', function (): void {
    $backlog = app(RelayBacklog::class);

    expect($backlog->depth()->waiting)->toBe(0)
        ->and($backlog->depth()->oldestUndeliveredAt)->toBeNull()
        ->and($backlog->depth()->oldestAgeSeconds())->toBe(0);

    app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 1], 'org_a'));
    app(EventBus::class)->emit(new DomainEvent('user.created', ['n' => 2], 'org_a'));

    $depth = $backlog->depth();

    expect($depth->waiting)->toBe(2)
        ->and($depth->inFlight)->toBe(0)
        ->and($depth->total())->toBe(2)
        ->and($depth->oldestUndeliveredAt)->not->toBeNull();

    app(EventBus::class)->flushPending();

    expect($backlog->depth()->total())->toBe(0);
});

it('counts a live claim as in flight and a stale one as waiting again', function (): void {
    config(['cbox-id.events.reclaim_after_seconds' => 300]);

    app(EventBus::class)->emit(new DomainEvent('user.created', [], 'org_a'));
    Event::query()->update(['claimed_at' => now()]);

    expect(app(RelayBacklog::class)->depth())
        ->waiting->toBe(0)
        ->inFlight->toBe(1);

    // A relay that died mid-pass: past the reclaim window the row is pickable again,
    // and the backlog says so rather than hiding it as "in flight".
    $this->travel(301)->seconds();

    expect(app(RelayBacklog::class)->depth())
        ->waiting->toBe(1)
        ->inFlight->toBe(0);
});

it('reports the backlog through the console command', function (): void {
    app(EventBus::class)->emit(new DomainEvent('user.created', [], 'org_a'));

    $this->artisan('cbox-id:events:backlog --json')->assertSuccessful();

    // Usable as a health check: non-zero once the waiting depth crosses the bound.
    $this->artisan('cbox-id:events:backlog --fail-over=1')->assertFailed();
    $this->artisan('cbox-id:events:backlog --fail-over=5')->assertSuccessful();
});

it('falls back to the safe cadence rather than leaving the relay unscheduled', function (): void {
    expect(RelayCadence::fromConfig('every_five_minutes'))->toBe(RelayCadence::EveryFiveMinutes)
        ->and(RelayCadence::fromConfig('nonsense'))->toBe(RelayCadence::EveryMinute)
        ->and(RelayCadence::fromConfig(null))->toBe(RelayCadence::EveryMinute)
        ->and(RelayCadence::fromConfig(42))->toBe(RelayCadence::EveryMinute);
});
