<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Enums;

/**
 * The catalog of resource-lifecycle events a webhook endpoint may subscribe to.
 * These are the domain events a downstream integration cares about — not the full
 * internal audit stream. Subscription is deny-by-default: an endpoint may register
 * for a value in this catalog (or the {@see self::WILDCARD} "all events"), and
 * nothing else, so a typo silently subscribing to a never-fired event is caught at
 * registration rather than discovered as missing deliveries in production.
 */
enum WebhookEventType: string
{
    case UserCreated = 'user.created';
    case UserUpdated = 'user.updated';
    case UserDeactivated = 'user.deactivated';

    case OrganizationCreated = 'organization.created';
    case OrganizationSuspended = 'organization.suspended';
    case OrganizationReactivated = 'organization.reactivated';
    case OrganizationSettingsUpdated = 'organization.settings_updated';
    case OrganizationMemberAdded = 'organization.member_added';
    case OrganizationMemberRemoved = 'organization.member_removed';
    case OrganizationMemberRoleChanged = 'organization.member_role_changed';
    case OrganizationInvitationCreated = 'organization.invitation_created';
    case OrganizationInvitationAccepted = 'organization.invitation_accepted';

    case RoleAssigned = 'role.assigned';

    case DirectoryUserProvisioned = 'directory.user.provisioned';
    case DirectoryUserDeprovisioned = 'directory.user.deprovisioned';
    case DirectoryUserDeactivated = 'directory.user.deactivated';
    case DirectoryGroupMembershipChanged = 'directory.group.membership_changed';

    case DomainAdded = 'domain.added';
    case DomainRemoved = 'domain.removed';
    case DomainVerified = 'domain.verified';

    case ConnectionActivated = 'connection.activated';

    case EntitlementSet = 'entitlement.set';
    case EntitlementUpdated = 'entitlement.updated';
    case EntitlementRevoked = 'entitlement.revoked';

    case VaultGrantCreated = 'vault.grant.created';
    case VaultGrantRevoked = 'vault.grant.revoked';
    case VaultSecretRevoked = 'vault.secret.revoked';

    case GovernanceAccessRevoked = 'governance.access.revoked';

    /** A subscription to every catalogued event, present and future. */
    public const WILDCARD = '*';

    /**
     * Whether a subscription string is acceptable: a known catalog event or the
     * wildcard. Used to validate an endpoint's requested `event_types`.
     */
    public static function subscribable(string $eventType): bool
    {
        return $eventType === self::WILDCARD || self::tryFrom($eventType) !== null;
    }

    /**
     * The full catalog as `value => label`, for discovery/documentation and the
     * subscription picker in a console.
     *
     * @return array<string, string>
     */
    public static function catalog(): array
    {
        $catalog = [];

        foreach (self::cases() as $case) {
            $catalog[$case->value] = $case->label();
        }

        return $catalog;
    }

    public function label(): string
    {
        return match ($this) {
            self::UserCreated => 'A user was created',
            self::UserUpdated => 'A user was updated',
            self::UserDeactivated => 'A user was deactivated',
            self::OrganizationCreated => 'An organization was created',
            self::OrganizationSuspended => 'An organization was suspended',
            self::OrganizationReactivated => 'A suspended organization was reactivated',
            self::OrganizationSettingsUpdated => 'An organization\'s settings were updated',
            self::OrganizationMemberAdded => 'A member was added to an organization',
            self::OrganizationMemberRemoved => 'A member was removed from an organization',
            self::OrganizationMemberRoleChanged => 'A member\'s role changed',
            self::OrganizationInvitationCreated => 'An invitation was created',
            self::OrganizationInvitationAccepted => 'An invitation was accepted',
            self::RoleAssigned => 'A role was assigned to a member',
            self::DirectoryUserProvisioned => 'A directory user was provisioned (SCIM)',
            self::DirectoryUserDeprovisioned => 'A directory user was deprovisioned (SCIM)',
            self::DirectoryUserDeactivated => 'A directory user was deactivated (SCIM)',
            self::DirectoryGroupMembershipChanged => 'A directory group membership changed (SCIM)',
            self::DomainAdded => 'A domain was added',
            self::DomainRemoved => 'A domain was removed',
            self::DomainVerified => 'A domain was verified',
            self::ConnectionActivated => 'An SSO connection was activated',
            self::EntitlementSet => 'An entitlement was set',
            self::EntitlementUpdated => 'An entitlement was updated',
            self::EntitlementRevoked => 'An entitlement was revoked',
            self::VaultGrantCreated => 'A token-vault grant was created',
            self::VaultGrantRevoked => 'A token-vault grant was revoked',
            self::VaultSecretRevoked => 'A token-vault secret was revoked',
            self::GovernanceAccessRevoked => 'A governance review revoked access',
        };
    }
}
