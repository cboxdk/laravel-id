<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Listeners\RecordUsageOnDomainEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('records and totals a metric', function (): void {
    $meter = app(UsageMeter::class);
    $meter->record('login', 1, 'org_a');
    $meter->record('login', 2, 'org_a');

    expect($meter->total('login', 'org_a'))->toBe(3);
});

it('scopes totals by organization and sums across the env when org is null', function (): void {
    $meter = app(UsageMeter::class);
    $meter->record('login', 1, 'org_a');
    $meter->record('login', 5, 'org_b');

    expect($meter->total('login', 'org_a'))->toBe(1)
        ->and($meter->total('login', 'org_b'))->toBe(5)
        ->and($meter->total('login', null))->toBe(6);
});

it('keeps a system-scoped (org-less) count out of any org total', function (): void {
    $meter = app(UsageMeter::class);
    $meter->record('user.created'); // no org

    expect($meter->total('user.created', null))->toBe(1)
        ->and($meter->total('user.created', 'org_a'))->toBe(0);
});

it('returns a per-day series and a snapshot', function (): void {
    $meter = app(UsageMeter::class);
    $meter->record('login', 2, 'org_a');
    $meter->record('mfa.enrolled', 1, 'org_a');

    $today = now();
    $series = $meter->series('login', 'org_a', $today->copy()->subDay(), $today->copy()->addDay());
    expect($series[$today->format('Y-m-d')])->toBe(2);

    $snapshot = $meter->snapshot('org_a', $today->copy()->subDay(), $today->copy()->addDay());
    expect($snapshot)->toBe(['login' => 2, 'mfa.enrolled' => 1]);
});

it('accumulates across many increments without loss', function (): void {
    $meter = app(UsageMeter::class);
    for ($i = 0; $i < 25; $i++) {
        $meter->record('login', 1, 'org_a');
    }

    expect($meter->total('login', 'org_a'))->toBe(25);
});

it('is environment-scoped — a counter in one env is invisible in another', function (): void {
    $this->runAsEnvironment('env_a', fn () => app(UsageMeter::class)->record('login', 3, 'org_a'));

    $this->runAsEnvironment('env_b', function (): void {
        expect(app(UsageMeter::class)->total('login', 'org_a'))->toBe(0);
    });

    $this->runAsEnvironment('env_a', function (): void {
        expect(app(UsageMeter::class)->total('login', 'org_a'))->toBe(3);
    });
})->group('isolation');

it('auto-meters a domain event off the outbox relay', function (): void {
    app(EventBus::class)->emit(new DomainEvent('organization.created', [], 'org_x'));
    app(EventBus::class)->flushPending();

    // Recorded under the shared, billing-aligned metric key.
    expect(app(UsageMeter::class)->total('auth.organization', 'org_x'))->toBe(1);
});

it('meters a delivered event exactly once, even on redelivery', function (): void {
    $event = app(EventBus::class)->emit(new DomainEvent('user.login', [], 'org_a'));
    $listener = app(RecordUsageOnDomainEvent::class);

    $listener->handle(new EventDelivered($event));
    $listener->handle(new EventDelivered($event)); // at-least-once redelivery

    expect(app(UsageMeter::class)->total('auth.login', 'org_a'))->toBe(1);
});

it('ignores an unmapped event type', function (): void {
    $event = app(EventBus::class)->emit(new DomainEvent('some.unmapped_event', [], 'org_a'));
    app(RecordUsageOnDomainEvent::class)->handle(new EventDelivered($event));

    expect(app(UsageMeter::class)->total('some.unmapped_event', 'org_a'))->toBe(0);
});
