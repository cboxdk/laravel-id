<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Contracts;

use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Governance\Exceptions\CampaignClosed;
use Cbox\Id\Governance\Exceptions\UnknownCampaign;
use Cbox\Id\Governance\Exceptions\UnknownCertificationItem;
use Cbox\Id\Governance\Models\CertificationCampaign;
use Cbox\Id\Governance\Models\CertificationItem;
use DateTimeInterface;

/**
 * Access certification (periodic access review): snapshot the access grants within
 * an organization, put each in front of a reviewer to certify or revoke, and on
 * close APPLY every revoke against the real access contracts.
 *
 * v1 governs RBAC role assignments and organization memberships — the two
 * subject-centric grants that are cleanly enumerable and immediately revocable.
 * Grants are captured at their own organization (a role inherited from an ancestor
 * org is certified at that ancestor, where the assignment physically lives).
 *
 * Everything is environment-owned and audited; each decision and application is
 * correlated by the campaign id on the audit trail.
 */
interface AccessReviews
{
    /**
     * Open a campaign: snapshot every DIRECT role assignment and membership in the
     * organization as pending items. `pendingPolicy` decides the fate of items still
     * un-reviewed at close (default Revoke — deny-by-default).
     */
    public function open(
        string $organizationId,
        string $name,
        ?DateTimeInterface $dueAt = null,
        PendingPolicy $pendingPolicy = PendingPolicy::Revoke,
        ?string $createdBy = null,
    ): CertificationCampaign;

    /**
     * Certify an item (the access is confirmed to still be needed).
     *
     * @throws UnknownCertificationItem
     * @throws CampaignClosed
     */
    public function certify(string $itemId, string $reviewerId, string $organizationId, ?string $note = null): CertificationItem;

    /**
     * Revoke an item (the access should be removed). The actual removal happens when
     * the campaign closes, so a reviewer can change their mind while it is open.
     *
     * @throws UnknownCertificationItem
     * @throws CampaignClosed
     */
    public function revoke(string $itemId, string $reviewerId, string $organizationId, ?string $note = null): CertificationItem;

    /**
     * Close the campaign: apply every revoked item (and every pending item per the
     * campaign's PendingPolicy) against the real access contracts, then mark it
     * closed. A revoke that the domain refuses (e.g. removing an org's last owner) is
     * recorded on the item as un-applied with a reason, and audited — never silently
     * dropped. Idempotent: closing an already-closed campaign is a no-op.
     *
     * @throws UnknownCampaign
     */
    public function close(string $campaignId, string $organizationId): CertificationCampaign;

    /**
     * The items of a campaign (the review worklist / evidence).
     *
     * @return list<CertificationItem>
     */
    public function itemsFor(string $campaignId): array;
}
