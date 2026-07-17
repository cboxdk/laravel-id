<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage;

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Enums\UsageMetric;
use Cbox\Id\Kernel\Usage\ValueObjects\ReconciliationResult;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipStatus;

/**
 * The drift safety net over the metering outbox. Delivery is at-least-once and each
 * metric is deduped, so transient failures self-heal — but an event that is NEVER
 * emitted (a bug, a non-atomic write lost to a crash) drifts the meter from reality
 * silently, and nothing else catches it. This reconciler periodically compares the
 * meter against ground truth and closes any gap.
 *
 * Seats/membership is the reconcilable dimension: current active members is the
 * authority, and it must equal metered joins minus departures. When they diverge, the
 * local meter is corrected immediately and a `usage.reconciled` event fans the same
 * correction out to downstream stores (billing), so both converge on truth. Every
 * reconciliation with a non-zero drift is recorded in the tamper-evident audit log.
 */
final class UsageReconciler
{
    public function __construct(
        private readonly Memberships $memberships,
        private readonly UsageMeter $meter,
        private readonly EventBus $events,
        private readonly AuditLog $audit,
    ) {}

    public function reconcileMembership(string $organizationId): ReconciliationResult
    {
        $expected = $this->memberships->forOrganization($organizationId)
            ->filter(fn ($membership): bool => $membership->status === MembershipStatus::Active)
            ->count();

        $metered = $this->meter->total(UsageMetric::MemberAdded->value, $organizationId)
            - $this->meter->total(UsageMetric::MemberRemoved->value, $organizationId);

        $drift = $expected - $metered;

        if ($drift === 0) {
            return new ReconciliationResult($organizationId, 'membership', $expected, $metered, 0, false);
        }

        // A positive drift means missed joins (short on member_added); a negative one
        // means missed departures (short on member_removed). record() only takes a
        // positive count, so map the sign to the metric and use the magnitude.
        $metric = $drift > 0 ? UsageMetric::MemberAdded : UsageMetric::MemberRemoved;
        $units = abs($drift);

        // Correct the local meter now; fan the same correction out for downstream
        // stores (the billing bridge applies it to its own buffer).
        $this->meter->record($metric->value, $units, $organizationId);

        $this->events->emit(new DomainEvent('usage.reconciled', [
            'dimension' => 'membership',
            'metric' => $metric->value,
            'units' => $units,
        ], $organizationId));

        $this->audit->record(new AuditEvent(
            action: 'usage.drift_reconciled',
            actorType: ActorType::System,
            organizationId: $organizationId,
            context: ['dimension' => 'membership', 'expected' => $expected, 'metered' => $metered, 'drift' => $drift],
        ));

        return new ReconciliationResult($organizationId, 'membership', $expected, $metered, $drift, true);
    }
}
