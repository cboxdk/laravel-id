<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage;

use Cbox\Id\Kernel\Usage\Enums\UsageMetric;

/**
 * The single source of truth mapping a domain-event `type` to the {@see UsageMetric}
 * it meters. Used by the framework's own {@see Listeners\RecordUsageOnDomainEvent}
 * (local analytics) AND by any downstream bridge that forwards the same events to
 * billing — so both meter the same events under the same shared vocabulary.
 */
class EventMetricMap
{
    /**
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
        'organization.member_removed' => UsageMetric::MemberRemoved,
        'organization.invitation_created' => UsageMetric::InvitationCreated,
        'organization.invitation_accepted' => UsageMetric::InvitationAccepted,
        'role.assigned' => UsageMetric::RoleAssigned,
        'service_account.created' => UsageMetric::ServiceAccountCreated,
        'oauth.backchannel_authentication_requested' => UsageMetric::CibaRequested,
        'domain.verified' => UsageMetric::DomainVerified,
        'governance.campaign_opened' => UsageMetric::GovernanceCampaignOpened,
        // SCIM/directory provisioning — an enterprise usage dimension on top of MAU
        // and seats. (SSO usage folds into user.login; SSO-as-a-feature is an
        // entitlement, not a metered event.)
        'directory.user.provisioned' => UsageMetric::DirectoryUserProvisioned,
    ];

    /**
     * The metric a domain-event type meters, or null if it is not metered.
     */
    public static function for(string $eventType): ?UsageMetric
    {
        return self::MAP[$eventType] ?? null;
    }

    /**
     * The whole event-type → metric mapping.
     *
     * @return array<string, UsageMetric>
     */
    public static function all(): array
    {
        return self::MAP;
    }
}
