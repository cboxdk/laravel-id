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
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\LastOwner;
use Cbox\Id\Organization\Models\Membership;
use DateTimeInterface;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Str;
use LogicException;

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
    // Lazy per-call resolution of the ambient environment. This class is a `singleton`
    // (GovernanceServiceProvider) and EnvironmentContext is `scoped`, so injecting it here
    // would pin a queue worker to the first job's environment for the life of the process.
    use ResolvesEnvironment;

    public function __construct(
        private readonly Roles $roles,
        private readonly Memberships $memberships,
        private readonly AuditLog $audit,
        private readonly EventBus $events,
    ) {}

    public function open(
        ?string $organizationId,
        string $name,
        ?DateTimeInterface $dueAt = null,
        PendingPolicy $pendingPolicy = PendingPolicy::Revoke,
        ?string $createdBy = null,
    ): CertificationCampaign {
        $this->environments()->requireEnvironment();

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

    public function certify(string $itemId, string $reviewerId, ?string $organizationId, ?string $note = null): CertificationItem
    {
        return $this->decide($itemId, $reviewerId, $organizationId, ReviewDecision::Certified, 'governance.item_certified', $note);
    }

    public function revoke(string $itemId, string $reviewerId, ?string $organizationId, ?string $note = null): CertificationItem
    {
        return $this->decide($itemId, $reviewerId, $organizationId, ReviewDecision::Revoked, 'governance.item_revoked', $note);
    }

    public function close(string $campaignId, ?string $organizationId): CertificationCampaign
    {
        $this->environments()->requireEnvironment();

        // Scope the lookup to the acting org. Closing APPLIES every revoke against real
        // memberships and roles, so a campaign id from another tenant would strip that
        // tenant's access. Filtering in the query (rather than fetch-then-compare) means
        // a foreign id is indistinguishable from a missing one — and a tenant naming the
        // environment's campaign is refused the same way, because null only ever matches
        // a null and a tenant's id never does.
        $campaign = $this->ownedBy(CertificationCampaign::query()->whereKey($campaignId), $organizationId)
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
        return array_values($this->items($campaignId)->orderBy('id')->get()->all());
    }

    /** @return LengthAwarePaginator<int, CertificationItem> */
    public function paginateItemsFor(string $campaignId, int $perPage = 25): LengthAwarePaginator
    {
        return $this->items($campaignId)->orderBy('id')->paginate($perPage);
    }

    public function countItemsFor(string $campaignId): int
    {
        return $this->items($campaignId)->count();
    }

    /**
     * The items of a campaign, fenced to the organization that campaign belongs to.
     *
     * THE CAMPAIGN ID WAS THE WHOLE AUTHORIZATION. `CertificationItem` is environment-owned
     * and not tenant-owned — many organizations share one environment — so a reader that
     * filtered on `campaign_id` alone would hand any caller holding an id another tenant's
     * entire certification worklist: every reviewed subject, the role or membership each
     * holds, and the reviewer's decisions.
     *
     * No caller could reach it today, because the console re-resolves the campaign with its
     * own organization predicate before every read. That is the fence living outside the
     * contract, one call site's vigilance away from being gone — the same shape that shipped
     * a cross-organization IDOR on this very console. The predicate belongs in the query.
     *
     * A campaign that does not resolve (wrong environment, or simply absent) yields a query
     * that matches nothing rather than one that matches everything.
     *
     * @return Builder<CertificationItem>
     */
    private function items(string $campaignId): Builder
    {
        $campaign = CertificationCampaign::query()->whereKey($campaignId)->first(['id', 'organization_id']);

        // An ENVIRONMENT campaign has a null organization, and its items do too; the
        // fence then pins the items to the environment plane, so an organization's item
        // can never be read through one. A campaign that does not resolve still matches
        // nothing — null is a statement about the campaign, never about its absence.
        if ($campaign === null) {
            return CertificationItem::query()->whereRaw('1 = 0');
        }

        return $this->ownedBy(
            CertificationItem::query()->where('campaign_id', $campaignId),
            $campaign->organization_id,
        );
    }

    /**
     * `organization_id = ?`, where null means the environment plane (`IS NULL`) rather
     * than a comparison with NULL that matches nothing.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  Builder<TModel>  $query
     * @return Builder<TModel>
     */
    private function ownedBy(Builder $query, ?string $organizationId): Builder
    {
        return $organizationId === null
            ? $query->whereNull('organization_id')
            : $query->where('organization_id', $organizationId);
    }

    /**
     * Capture every direct role assignment and membership in the org as pending items —
     * or, for the environment's own campaign, every environment-wide role grant.
     */
    private function snapshot(CertificationCampaign $campaign, ?string $organizationId): int
    {
        $count = 0;

        if ($organizationId === null) {
            // The grants that belong to no organization, and that no organization's
            // campaign could ever see. A staff role held across every customer is the
            // largest grant in the system, and until this existed it was never reviewed.
            foreach ($this->roles->assignmentsEverywhere() as $assignment) {
                $this->makeItem($campaign, AccessKind::EnvironmentRole, $assignment->user_id, $assignment->role_id, null, $assignment->source->value);
                $count++;
            }

            return $count;
        }

        foreach ($this->roles->assignmentsInOrganization($organizationId) as $assignment) {
            $this->makeItem($campaign, AccessKind::Role, $assignment->user_id, $assignment->role_id, $assignment->organization_id, $assignment->source->value);
            $count++;
        }

        foreach ($this->memberships->forOrganization($organizationId) as $membership) {
            $this->makeItem($campaign, AccessKind::Membership, $membership->user_id, $membership->role->value, $organizationId, null);
            $count++;
        }

        return $count;
    }

    private function makeItem(
        CertificationCampaign $campaign,
        AccessKind $type,
        string $subjectId,
        string $accessRef,
        ?string $organizationId,
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

    private function decide(string $itemId, string $reviewerId, ?string $organizationId, ReviewDecision $decision, string $action, ?string $note): CertificationItem
    {
        $this->environments()->requireEnvironment();

        $item = CertificationItem::query()->whereKey($itemId)->first();

        if ($item === null) {
            throw UnknownCertificationItem::forId($itemId);
        }

        // The item's campaign must belong to the ACTING org — an item id alone is not
        // authorization to decide it, and a decision here is applied on close.
        $campaign = $this->ownedBy(CertificationCampaign::query()->whereKey($item->campaign_id), $organizationId)
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

    /**
     * The organization an org-plane item's grant lives in. Such an item always has one —
     * only an environment item has none — so a null here is a corrupt row, and revoking
     * "in no organization" must never be guessed at.
     */
    private function itemOrganization(CertificationItem $item): string
    {
        if ($item->organization_id === null) {
            throw new LogicException("Certification item [{$item->id}] reviews an organization grant but names no organization.");
        }

        return $item->organization_id;
    }

    private function applyRevoke(CertificationCampaign $campaign, CertificationItem $item): void
    {
        try {
            match ($item->access_type) {
                AccessKind::Role => $this->roles->unassign($this->itemOrganization($item), $item->subject_id, $item->access_ref),
                AccessKind::Membership => $this->memberships->remove($this->itemOrganization($item), $item->subject_id),
                // The environment-wide grant itself — every organization at once, which
                // is what certifying it away means.
                AccessKind::EnvironmentRole => $this->roles->unassignEverywhere($item->subject_id, $item->access_ref),
            };
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
