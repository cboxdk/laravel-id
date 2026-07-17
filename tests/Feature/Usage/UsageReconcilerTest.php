<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\UsageReconciler;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('detects seat drift, corrects the meter, and emits + audits a reconciliation', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    // Ground truth: 3 active members. Their member_added events sit unrelayed on the
    // outbox, so the meter reads 0 — a drift of +3, as if those events were lost.
    $memberships = app(Memberships::class);
    $memberships->add($org->id, 'u1', 'member');
    $memberships->add($org->id, 'u2', 'member');
    $memberships->add($org->id, 'u3', 'member');

    $meter = app(UsageMeter::class);
    expect($meter->total('auth.member_added', $org->id))->toBe(0);

    $result = app(UsageReconciler::class)->reconcileMembership($org->id);

    expect($result->expected)->toBe(3)
        ->and($result->metered)->toBe(0)
        ->and($result->drift)->toBe(3)
        ->and($result->corrected)->toBeTrue()
        ->and($meter->total('auth.member_added', $org->id))->toBe(3);   // meter now matches truth

    $events->assertEmitted('usage.reconciled');           // fans the correction to downstream stores
    $audit->assertRecorded('usage.drift_reconciled');     // recorded in the tamper-evident log
});

it('corrects an over-count by metering the missing departures', function (): void {
    $org = $this->makeOrganization();
    $this->fakeEvents();
    $this->fakeAudit();

    app(Memberships::class)->add($org->id, 'u1', 'member');   // ground truth: 1 active member

    // The meter over-counts: 3 joins recorded but only 1 departure — net 2 vs truth 1.
    $meter = app(UsageMeter::class);
    $meter->record('auth.member_added', 3, $org->id);
    $meter->record('auth.member_removed', 1, $org->id);

    $result = app(UsageReconciler::class)->reconcileMembership($org->id);

    // drift = expected(1) - metered(2) = -1 → record one missing removal.
    expect($result->drift)->toBe(-1)
        ->and($result->corrected)->toBeTrue()
        ->and($meter->total('auth.member_removed', $org->id))->toBe(2);   // net now 3-2 = 1 = truth
});

it('is a no-op when the meter already matches ground truth', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();

    app(Memberships::class)->add($org->id, 'u1', 'member');
    app(UsageMeter::class)->record('auth.member_added', 1, $org->id);

    $result = app(UsageReconciler::class)->reconcileMembership($org->id);

    expect($result->drift)->toBe(0)->and($result->corrected)->toBeFalse();
    $events->assertNotEmitted('usage.reconciled');
});
