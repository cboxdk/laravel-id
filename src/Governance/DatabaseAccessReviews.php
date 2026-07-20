<?php

declare(strict_types=1);

namespace Cbox\Id\Governance;

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Enums\AccessKind;
use Cbox\Id\Governance\Enums\CampaignStatus;
use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Governance\Enums\ReviewDecision;
use Cbox\Id\Governance\Exceptions\CampaignClosed;
use Cbox\Id\Governance\Exceptions\UnknownCampaign;
use Cbox\Id\Governance\Exceptions\UnknownCertificationItem;
use Cbox\Id\Governance\Models\CertificationCampaign;
use Cbox\Id\Governance\Models\CertificationItem;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\LastOwner;
use Cbox\Id\Organization\Models\Membership;
use DateTimeInterface;
use Illuminate\Support\Str;

/**
 * Database-backed {@see AccessReviews}. This class carries the certification
 * guarantees: it snapshots real access grants, records reviewer decisions, and on
 * close APPLIES revokes against the real access contracts ({@see Roles::unassign()},
 * {@see Memberships::remove()}) — a revoke the domain refuses is recorded and audited,
 * never silently dropped. Every decision and application is correlated by the
 * campaign id on the hash-chained audit trail.
 */
class DatabaseAccessReviews implements AccessReviews
{
    public function __construct(
        private readonly Roles $roles,
        private readonly Memberships $memberships,
        private readonly AuditLog $audit,
        private readonly EventBus $events,
        private readonly EnvironmentContext $environments,
    ) {}

    public function open(
        string $organizationId,
        string $name,
        ?DateTimeInterface $dueAt = null,
        PendingPolicy $pendingPolicy = PendingPolicy::Revoke,
        ?string $createdBy = null,
    ): CertificationCampaign {
        $this->environments->requireEnvironment();

        $campaign = new CertificationCampaign;
        $campaign->id = (string) Str::ulid();
        $campaign->fill([
            'organization_id' => $organizationId,
            'name' => $name,
            'status' => CampaignStatus::Open,
            'pending_policy' => $pendingPolicy,
            'due_at' => $dueAt,
            'created_by' => $createdBy,
        ]);
        $campaign->save();

        $count = $this->snapshot($campaign, $organizationId);

        $this->audit->record(new AuditEvent(
            action: 'governance.campaign_opened',
            actorType: ActorType::System,
            actorId: $createdBy,
            organizationId: $organizationId,
            targetType: 'governance_campaign',
            targetId: $campaign->id,
            context: ['name' => $name, 'items' => $count],
        ));
        $this->events->emit(new DomainEvent(
            'governance.campaign_opened',
            ['campaign_id' => $campaign->id, 'items' => $count],
            $organizationId,
        ));

        return $campaign;
    }

    public function certify(string $itemId, string $reviewerId, string $organizationId, ?string $note = null): CertificationItem
    {
        return $this->decide($itemId, $reviewerId, $organizationId, ReviewDecision::Certified, 'governance.item_certified', $note);
    }

    public function revoke(string $itemId, string $reviewerId, string $organizationId, ?string $note = null): CertificationItem
    {
        return $this->decide($itemId, $reviewerId, $organizationId, ReviewDecision::Revoked, 'governance.item_revoked', $note);
    }

    public function close(string $campaignId, string $organizationId): CertificationCampaign
    {
        $this->environments->requireEnvironment();

        // Scope the lookup to the acting org. Closing APPLIES every revoke against real
        // memberships and roles, so a campaign id from another tenant would strip that
        // tenant's access. Filtering in the query (rather than fetch-then-compare) means
        // a foreign id is indistinguishable from a missing one.
        $campaign = CertificationCampaign::query()
            ->whereKey($campaignId)
            ->where('organization_id', $organizationId)
            ->first();

        if ($campaign === null) {
            throw UnknownCampaign::forId($campaignId);
        }

        // Idempotent: re-closing does nothing (and never re-applies revokes).
        if ($campaign->isClosed()) {
            return $campaign;
        }

        foreach ($this->itemsFor($campaignId) as $item) {
            $this->settle($campaign, $item);
        }

        $campaign->status = CampaignStatus::Closed;
        $campaign->closed_at = now();
        $campaign->save();

        $this->audit->record(new AuditEvent(
            action: 'governance.campaign_closed',
            actorType: ActorType::System,
            organizationId: $campaign->organization_id,
            targetType: 'governance_campaign',
            targetId: $campaign->id,
        ));
        $this->events->emit(new DomainEvent(
            'governance.campaign_closed',
            ['campaign_id' => $campaign->id],
            $campaign->organization_id,
        ));

        return $campaign;
    }

    public function itemsFor(string $campaignId): array
    {
        return array_values(CertificationItem::query()
            ->where('campaign_id', $campaignId)
            ->orderBy('id')
            ->get()
            ->all());
    }

    /**
     * Capture every direct role assignment and membership in the org as pending items.
     */
    private function snapshot(CertificationCampaign $campaign, string $organizationId): int
    {
        $count = 0;

        foreach ($this->roles->assignmentsInOrganization($organizationId) as $assignment) {
            $this->makeItem($campaign, AccessKind::Role, $assignment->user_id, $assignment->role_id, $assignment->organization_id, $assignment->source->value);
            $count++;
        }

        foreach ($this->memberships->forOrganization($organizationId) as $membership) {
            $this->makeItem($campaign, AccessKind::Membership, $membership->user_id, $membership->role, $organizationId, null);
            $count++;
        }

        return $count;
    }

    private function makeItem(
        CertificationCampaign $campaign,
        AccessKind $type,
        string $subjectId,
        string $accessRef,
        string $organizationId,
        ?string $source,
    ): void {
        $item = new CertificationItem;
        $item->id = (string) Str::ulid();
        $item->fill([
            'campaign_id' => $campaign->id,
            'access_type' => $type,
            'subject_id' => $subjectId,
            'access_ref' => $accessRef,
            'organization_id' => $organizationId,
            'source' => $source,
            'decision' => ReviewDecision::Pending,
            'applied' => false,
        ]);
        $item->save();
    }

    private function decide(string $itemId, string $reviewerId, string $organizationId, ReviewDecision $decision, string $action, ?string $note): CertificationItem
    {
        $this->environments->requireEnvironment();

        $item = CertificationItem::query()->whereKey($itemId)->first();

        if ($item === null) {
            throw UnknownCertificationItem::forId($itemId);
        }

        // The item's campaign must belong to the ACTING org — an item id alone is not
        // authorization to decide it, and a decision here is applied on close.
        $campaign = CertificationCampaign::query()
            ->whereKey($item->campaign_id)
            ->where('organization_id', $organizationId)
            ->first();

        if ($campaign === null || $campaign->isClosed()) {
            throw CampaignClosed::forId($item->campaign_id);
        }

        $item->decision = $decision;
        $item->reviewer_id = $reviewerId;
        $item->decided_by = $reviewerId;
        $item->decided_at = now();
        $item->note = $note;
        $item->save();

        $this->audit->record(AuditEvent::forUser(
            $action,
            $reviewerId,
            $campaign->organization_id,
            ['campaign_id' => $campaign->id, 'access_type' => $item->access_type->value, 'access_ref' => $item->access_ref, 'subject_id' => $item->subject_id],
        ));

        return $item;
    }

    /**
     * Resolve one item at close: apply a revoke (explicit, or pending under a Revoke
     * policy) against the real access contract; a pending item under a Certify policy
     * is auto-certified; an already-certified item is left alone.
     */
    private function settle(CertificationCampaign $campaign, CertificationItem $item): void
    {
        $decision = $item->decision;

        if ($decision === ReviewDecision::Pending) {
            // The un-reviewed item takes the campaign's pending policy, attributed to
            // the system so the record shows it was not a human decision.
            $decision = $campaign->pending_policy === PendingPolicy::Revoke
                ? ReviewDecision::Revoked
                : ReviewDecision::Certified;
            $item->decision = $decision;
            $item->decided_by = 'system';
            $item->decided_at = now();
            $item->note = 'pending at close (auto-'.$decision->value.')';
        }

        if ($decision !== ReviewDecision::Revoked) {
            $item->save();

            return;
        }

        $this->applyRevoke($campaign, $item);
    }

    private function applyRevoke(CertificationCampaign $campaign, CertificationItem $item): void
    {
        try {
            if ($item->access_type === AccessKind::Role) {
                $this->roles->unassign($item->organization_id, $item->subject_id, $item->access_ref);
            } else {
                $this->memberships->remove($item->organization_id, $item->subject_id);
            }
        } catch (LastOwner $e) {
            // A domain guard refused the revoke (removing an org's last owner). Record
            // it as un-applied with the reason and audit it — never silently drop it.
            $item->applied = false;
            $item->application_note = 'blocked: '.$e->getMessage();
            $item->save();

            $this->audit->record(new AuditEvent(
                action: 'governance.access.revoke_blocked',
                actorType: ActorType::System,
                organizationId: $campaign->organization_id,
                targetType: 'user',
                targetId: $item->subject_id,
                context: ['campaign_id' => $campaign->id, 'access_type' => $item->access_type->value, 'access_ref' => $item->access_ref, 'reason' => 'last_owner'],
            ));

            return;
        }

        $item->applied = true;
        $item->save();

        $this->audit->record(new AuditEvent(
            action: 'governance.access.revoked',
            actorType: ActorType::System,
            organizationId: $campaign->organization_id,
            targetType: 'user',
            targetId: $item->subject_id,
            context: ['campaign_id' => $campaign->id, 'access_type' => $item->access_type->value, 'access_ref' => $item->access_ref],
        ));
    }
}
