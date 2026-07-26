<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Enums\UsageMetric;
use Cbox\Id\Kernel\Usage\Models\UsageCounter;
use Cbox\Id\Kernel\Usage\Testing\FakeUsageMeter;
use Cbox\Id\Kernel\Usage\Testing\InteractsWithUsage;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\ExpectationFailedException;

uses(RefreshDatabase::class, InteractsWithUsage::class);

/**
 * {@see FakeUsageMeter} and {@see InteractsWithUsage} ship to consumers, but
 * `fakeUsage()` was never called anywhere — a fake nobody exercises is a promise
 * nobody keeps. These tests use it exactly as a host app would: call the helper,
 * then run REAL platform code and assert on what the fake captured.
 */
it('is swapped in for the real meter by the shipped trait helper', function (): void {
    $fake = $this->fakeUsage();

    // The container hands the fake to everything that asks for a UsageMeter — which
    // is what makes the swap useful at all.
    expect(app(UsageMeter::class))->toBe($fake);
});

it('captures usage recorded by real platform code, not by the test', function (): void {
    $fake = $this->fakeUsage();

    // A genuine domain event through the outbox: the framework's own listener maps
    // the type to a metric and increments. Nothing here calls record() directly.
    app(EventBus::class)->emit(new DomainEvent('organization.created', ['id' => 'org_a'], 'org_a'));
    app(EventBus::class)->flushPending();

    $fake->assertIncremented(UsageMetric::OrganizationCreated->value);
    $fake->assertIncrementedCount(UsageMetric::OrganizationCreated->value, 1);

    expect($fake->recorded[0])->toBe([
        'metric' => UsageMetric::OrganizationCreated->value,
        'count' => 1,
        'organizationId' => 'org_a',
    ]);
});

it('answers total, series and snapshot from what it captured', function (): void {
    $fake = $this->fakeUsage();
    $meter = app(UsageMeter::class);

    $meter->record(UsageMetric::Login->value, 2, 'org_a');
    $meter->record(UsageMetric::Login->value, 3, 'org_a');
    $meter->record(UsageMetric::Login->value, 7, 'org_b');
    $meter->record(UsageMetric::UserCreated->value, 1, 'org_a');

    $since = now()->subDay();
    $until = now()->addDay();

    expect($meter->total(UsageMetric::Login->value, 'org_a'))->toBe(5)
        ->and($meter->total(UsageMetric::Login->value, 'org_b'))->toBe(7)
        // A null org means "across the whole environment", matching the real meter.
        ->and($meter->total(UsageMetric::Login->value))->toBe(12)
        ->and($meter->total('auth.never_recorded', 'org_a'))->toBe(0)
        ->and($meter->series(UsageMetric::Login->value, 'org_a', $since, $until))
        ->toBe([now()->format('Y-m-d') => 5])
        ->and($meter->series('auth.never_recorded', 'org_a', $since, $until))->toBe([])
        ->and($meter->snapshot('org_a', $since, $until))->toBe([
            UsageMetric::Login->value => 5,
            UsageMetric::UserCreated->value => 1,
        ]);
});

it('ignores a non-positive count and a blank metric, like the real meter', function (): void {
    $fake = $this->fakeUsage();
    $meter = app(UsageMeter::class);

    $meter->record(UsageMetric::Login->value, 0, 'org_a');
    $meter->record(UsageMetric::Login->value, -5, 'org_a');
    $meter->record('', 1, 'org_a');

    $fake->assertNothingRecorded();
});

it('does not record an un-mapped event type', function (): void {
    $fake = $this->fakeUsage();

    app(EventBus::class)->emit(new DomainEvent('something.not.metered', [], 'org_a'));
    app(EventBus::class)->flushPending();

    $fake->assertNothingRecorded();
});

it('exposes assertion helpers that actually fail when the expectation is not met', function (): void {
    // A fake whose assertions always pass is worse than none — pin that they don't.
    $fake = $this->fakeUsage();
    app(UsageMeter::class)->record(UsageMetric::Login->value, 1, 'org_a');

    expect(fn () => $fake->assertIncremented(UsageMetric::MfaEnrolled->value))
        ->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertIncrementedCount(UsageMetric::Login->value, 2))
        ->toThrow(ExpectationFailedException::class)
        ->and(fn () => $fake->assertNothingRecorded())
        ->toThrow(ExpectationFailedException::class);

    // The predicate form narrows to a specific recorded entry.
    $fake->assertIncremented(
        UsageMetric::Login->value,
        fn (array $entry): bool => $entry['organizationId'] === 'org_a' && $entry['count'] === 1,
    );

    expect(fn () => $fake->assertIncremented(UsageMetric::Login->value, fn (array $entry): bool => $entry['organizationId'] === 'org_z'))
        ->toThrow(ExpectationFailedException::class);
});

it('writes nothing to the usage counters while faked', function (): void {
    // The reason to reach for the fake at all: metering without touching the tables.
    $this->fakeUsage();

    app(UsageMeter::class)->record(UsageMetric::Login->value, 1, 'org_a');
    app(EventBus::class)->emit(new DomainEvent('organization.created', [], 'org_a'));
    app(EventBus::class)->flushPending();

    expect(UsageCounter::query()->count())->toBe(0);
});
