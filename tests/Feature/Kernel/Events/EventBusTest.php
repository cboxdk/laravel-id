<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event as EventFacade;

uses(RefreshDatabase::class);

/*
 * Pest ignores a file-level `@group` docblock — membership comes only from a `uses()` or
 * a per-test `->group()`. So the 17 files that declared the group this way contributed
 * ZERO tests to `--group=isolation`, including the environment-isolation proof itself,
 * while docs/core-concepts/environments.md tells operators to run exactly that command
 * as the evidence. A selector that silently omits its own load-bearing file is worse than
 * no selector.
 */
uses()->group('isolation');

it('persists an undelivered outbox row on emit', function (): void {
    $event = app(EventBus::class)->emit(new DomainEvent('organization.created', ['id' => 'org_1'], 'org_1'));

    expect($event->type)->toBe('organization.created')
        ->and($event->organization_id)->toBe('org_1')
        ->and($event->dispatched_at)->toBeNull()
        ->and(Event::query()->count())->toBe(1);
});

it('stamps the ambient environment on an emitted outbox row', function (): void {
    $env = app(EnvironmentContext::class)->current()?->environmentKey();

    $event = app(EventBus::class)->emit(new DomainEvent('organization.created', ['id' => 'org_1'], 'org_1'));

    expect($env)->not->toBeNull()
        ->and($event->environment_id)->toBe($env);
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

/**
 * @group isolation
 */
it('stamps the outbox with each job\'s OWN environment across a worker reset', function (): void {
    // EnvironmentContext is a `scoped` binding; this bus is a `singleton` and is itself
    // captured by other singletons (e.g. ManifestSyncService). A queue worker's
    // forgetScopedInstances() unsets the BINDING but does not reset the object, so a
    // captured manager keeps the first job's environment for the life of the process.
    //
    // For an EnvironmentOwned model that is harmless — BelongsToEnvironment::saving()
    // re-resolves per call and throws, so a stale context fails CLOSED. The outbox row
    // is deliberately NOT environment-owned, so nothing contradicts a stale value: job
    // B's payload would be stamped with job A's environment and, because flushPending()
    // routes purely on that column, delivered to job A's webhook subscribers. That is a
    // cross-environment disclosure to a third party's HTTP endpoint.
    $bus = app(EventBus::class);
    $context = app(EnvironmentContext::class);

    // Job A.
    $context->set(GenericEnvironment::of('env_a'));
    $bus->emit(new DomainEvent('thing.happened', ['job' => 'a']));

    // The between-jobs container reset a queue worker performs.
    $this->app->forgetScopedInstances();

    // Job B — same worker, same captured bus instance.
    $context = app(EnvironmentContext::class);
    $context->set(GenericEnvironment::of('env_b'));
    expect(app(EventBus::class))->toBe($bus); // the singleton really is reused
    $bus->emit(new DomainEvent('thing.happened', ['job' => 'b']));

    $stamped = Event::query()
        ->orderBy('occurred_at')
        ->get()
        ->mapWithKeys(fn (Event $e): array => [$e->payload['job'] => $e->environment_id])
        ->all();

    expect($stamped)->toBe(['a' => 'env_a', 'b' => 'env_b']);
});
