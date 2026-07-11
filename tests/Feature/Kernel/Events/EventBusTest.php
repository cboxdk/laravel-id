<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event as EventFacade;

uses(RefreshDatabase::class);

it('persists an undelivered outbox row on emit', function (): void {
    $event = app(EventBus::class)->emit(new DomainEvent('organization.created', ['id' => 'org_1'], 'org_1'));

    expect($event->type)->toBe('organization.created')
        ->and($event->organization_id)->toBe('org_1')
        ->and($event->dispatched_at)->toBeNull()
        ->and(Event::query()->count())->toBe(1);
});

it('persists nothing when the surrounding transaction rolls back (no dual-write)', function (): void {
    try {
        DB::transaction(function (): void {
            app(EventBus::class)->emit(new DomainEvent('should.not.survive'));
            throw new RuntimeException('rollback');
        });
    } catch (RuntimeException) {
        // expected
    }

    expect(Event::query()->count())->toBe(0);
});

it('delivers pending events, marks them dispatched, and is idempotent', function (): void {
    $bus = app(EventBus::class);
    $bus->emit(new DomainEvent('a'));
    $bus->emit(new DomainEvent('b'));

    expect($bus->flushPending())->toBe(2)
        ->and(Event::query()->whereNull('dispatched_at')->count())->toBe(0)
        ->and($bus->flushPending())->toBe(0); // nothing left to deliver
});

it('dispatches EventDelivered for each delivered event', function (): void {
    EventFacade::fake([EventDelivered::class]);

    $bus = app(EventBus::class);
    $bus->emit(new DomainEvent('organization.created', [], 'org_1'));
    $bus->flushPending();

    EventFacade::assertDispatched(EventDelivered::class, fn (EventDelivered $e): bool => $e->event->type === 'organization.created');
});
