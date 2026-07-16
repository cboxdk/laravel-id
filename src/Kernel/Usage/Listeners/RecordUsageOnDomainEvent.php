<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Listeners;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Usage\Contracts\UsageMeter;
use Cbox\Id\Kernel\Usage\Enums\UsageMetric;
use Illuminate\Support\Facades\DB;

/**
 * Meters domain events off the transactional outbox: it maps a delivered event's
 * `type` to a {@see UsageMetric} and increments the counter, attributed to the event's
 * organization. Decoupled from every emit site — new metered events are a map entry.
 *
 * Delivery is at-least-once, and a raw increment is not idempotent, so each event is
 * metered exactly once: an `insertOrIgnore` into `usage_metered_events` keyed on the
 * event id is the guard — only the first delivery (the insert that took) records.
 */
final class RecordUsageOnDomainEvent
{
    /**
     * Domain-event type → metric. Only mapped types are metered; everything else on
     * the bus is ignored.
     *
     * @var array<string, UsageMetric>
     */
    private const MAP = [
        'user.login' => UsageMetric::Login,
        'user.session_started' => UsageMetric::SessionStarted,
        'user.created' => UsageMetric::UserCreated,
        'user.mfa_enrolled' => UsageMetric::MfaEnrolled,
        'user.passkey_registered' => UsageMetric::PasskeyRegistered,
        'user.passkey_authenticated' => UsageMetric::PasskeyAuthenticated,
        'otp.issued' => UsageMetric::OtpIssued,
        'identity.linked' => UsageMetric::IdentityLinked,
        'organization.created' => UsageMetric::OrganizationCreated,
        'organization.member_added' => UsageMetric::MemberAdded,
        'organization.invitation_created' => UsageMetric::InvitationCreated,
        'organization.invitation_accepted' => UsageMetric::InvitationAccepted,
        'role.assigned' => UsageMetric::RoleAssigned,
        'service_account.created' => UsageMetric::ServiceAccountCreated,
        'oauth.backchannel_authentication_requested' => UsageMetric::CibaRequested,
        'domain.verified' => UsageMetric::DomainVerified,
        'governance.campaign_opened' => UsageMetric::GovernanceCampaignOpened,
    ];

    public function __construct(private readonly UsageMeter $meter) {}

    public function handle(EventDelivered $delivered): void
    {
        $metric = self::MAP[$delivered->event->type] ?? null;

        if (! $metric instanceof UsageMetric) {
            return;
        }

        // Exactly-once under at-least-once delivery: only the first delivery whose
        // marker insert takes (affected = 1) proceeds to increment.
        $fresh = DB::table('usage_metered_events')->insertOrIgnore([
            'event_id' => $delivered->event->id,
            'created_at' => now(),
        ]);

        if ($fresh === 0) {
            return;
        }

        $this->meter->record($metric->value, 1, $delivered->event->organization_id);
    }
}
