<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Enums;

use Cbox\Id\Webhooks\ValueObjects\WebhookEventDescriptor;

/**
 * A DOCUMENTED catalog of common resource-lifecycle events a webhook endpoint is
 * likely to subscribe to — for the console's subscription picker, discovery, and the
 * {@see self::WILDCARD} "all events" subscription. It is intentionally NOT an
 * allow-list: event types are open-ended (the domain and its plugins emit far more,
 * e.g. `auth.*`), so the registry accepts any non-empty type. Use this enum for the
 * known ones you want typed; a type absent from it is still a valid subscription.
 *
 * {@see self::catalogue()} is the one rendered form of it — group, label, a human
 * description, and whether the event is current or legacy — so a
 * console picker, an API and the docs all read the same list instead of each keeping
 * its own. A new case must add an arm to {@see label()}, {@see description()} and
 * {@see group()}; `match` makes a missing one a hard failure rather than a silent gap.
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

    // Tenancy lifecycle (1.19). The `membership.*` / `invitation.*` names supersede the
    // `organization.member_*` / `organization.invitation_*` ones above; both are emitted.
    case MembershipCreated = 'membership.created';
    case MembershipUpdated = 'membership.updated';
    case MembershipDeleted = 'membership.deleted';
    case InvitationCreated = 'invitation.created';
    case InvitationAccepted = 'invitation.accepted';
    case InvitationRevoked = 'invitation.revoked';
    case OrganizationUpdated = 'organization.updated';
    case OrganizationDeleted = 'organization.deleted';
    case OrganizationArchived = 'organization.archived';

    // Emitted before 1.19 but missing from this catalog.
    case UserLogin = 'user.login';
    case UserReactivated = 'user.reactivated';
    case IdentityLinked = 'identity.linked';
    case RoleUnassigned = 'role.unassigned';
    case RoleAssignedEverywhere = 'role.assigned_everywhere';
    case RoleUnassignedEverywhere = 'role.unassigned_everywhere';

    // Customer API keys and support sessions.
    case ApiKeyCreated = 'api_key.created';
    case ApiKeyRevoked = 'api_key.revoked';
    case SupportSessionStarted = 'support_session.started';

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
     * The full catalog as `value => label`. Kept for existing callers; new code renders
     * {@see catalogue()}, which also carries the description and the legacy/offered state.
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

    /**
     * Every catalogued event, grouped in display order, described once.
     *
     * @return list<WebhookEventDescriptor>
     */
    public static function catalogue(): array
    {
        $entries = array_map(static fn (self $case): WebhookEventDescriptor => $case->describe(), self::cases());

        $order = array_flip(array_map(static fn (WebhookEventGroup $g): string => $g->value, WebhookEventGroup::cases()));

        // Stable within a group: declaration order is the order events were catalogued.
        usort($entries, static fn (WebhookEventDescriptor $a, WebhookEventDescriptor $b): int => $order[$a->group->value] <=> $order[$b->group->value]);

        return $entries;
    }

    /**
     * The events a subscription picker should offer: emitted, and not superseded.
     *
     * @return list<self>
     */
    public static function offered(): array
    {
        return array_values(array_filter(self::cases(), static fn (self $case): bool => $case->describe()->isOffered()));
    }

    public function describe(): WebhookEventDescriptor
    {
        return new WebhookEventDescriptor(
            type: $this,
            group: $this->group(),
            label: $this->label(),
            description: $this->description(),
            supersededBy: $this->supersededBy(),
            emitted: $this->isEmitted(),
        );
    }

    public function group(): WebhookEventGroup
    {
        return match ($this) {
            self::UserCreated, self::UserUpdated, self::UserDeactivated, self::UserReactivated,
            self::UserLogin, self::IdentityLinked => WebhookEventGroup::Users,
            self::OrganizationCreated, self::OrganizationUpdated, self::OrganizationSuspended,
            self::OrganizationReactivated, self::OrganizationDeleted, self::OrganizationArchived,
            self::OrganizationSettingsUpdated => WebhookEventGroup::Organizations,
            self::MembershipCreated, self::MembershipUpdated, self::MembershipDeleted,
            self::OrganizationMemberAdded, self::OrganizationMemberRemoved,
            self::OrganizationMemberRoleChanged => WebhookEventGroup::Memberships,
            self::InvitationCreated, self::InvitationAccepted, self::InvitationRevoked,
            self::OrganizationInvitationCreated, self::OrganizationInvitationAccepted => WebhookEventGroup::Invitations,
            self::RoleAssigned, self::RoleUnassigned, self::RoleAssignedEverywhere,
            self::RoleUnassignedEverywhere => WebhookEventGroup::Roles,
            self::ApiKeyCreated, self::ApiKeyRevoked => WebhookEventGroup::ApiKeys,
            self::SupportSessionStarted => WebhookEventGroup::Support,
            self::DirectoryUserProvisioned, self::DirectoryUserDeprovisioned,
            self::DirectoryUserDeactivated, self::DirectoryGroupMembershipChanged => WebhookEventGroup::Directory,
            self::DomainAdded, self::DomainRemoved, self::DomainVerified => WebhookEventGroup::Domains,
            self::ConnectionActivated => WebhookEventGroup::Connections,
            self::EntitlementSet, self::EntitlementUpdated, self::EntitlementRevoked => WebhookEventGroup::Entitlements,
            self::VaultGrantCreated, self::VaultGrantRevoked, self::VaultSecretRevoked => WebhookEventGroup::TokenVault,
            self::GovernanceAccessRevoked => WebhookEventGroup::Governance,
        };
    }

    /**
     * The newer event that carries the same fact, for a legacy name kept only because
     * somebody may already subscribe to it.
     */
    public function supersededBy(): ?self
    {
        return match ($this) {
            self::OrganizationMemberAdded => self::MembershipCreated,
            self::OrganizationMemberRemoved => self::MembershipDeleted,
            self::OrganizationMemberRoleChanged => self::MembershipUpdated,
            self::OrganizationInvitationCreated => self::InvitationCreated,
            self::OrganizationInvitationAccepted => self::InvitationAccepted,
            self::OrganizationSettingsUpdated => self::OrganizationUpdated,
            self::OrganizationArchived => self::OrganizationDeleted,
            default => null,
        };
    }

    /**
     * Whether the framework actually emits this event today.
     *
     * The catalog once grew ahead of the code: nine names were recorded on the audit
     * trail and never put on the event bus, so a webhook subscribed to one received
     * nothing. Since 1.19 every catalogued event is emitted where its change happens, and
     * a test fails when a case is catalogued with no emitting source behind it. The flag
     * stays so that the rule — a picker never offers a subscription that cannot fire — has
     * one place to live if a case is ever catalogued ahead of its code again.
     */
    public function isEmitted(): bool
    {
        return true;
    }

    /**
     * What happened, and what the payload tells a receiver, in a sentence or two. Every
     * delivery also carries `organization_id` when the event belongs to one.
     */
    public function description(): string
    {
        return match ($this) {
            self::UserCreated => 'A user account was created in the environment. Payload: `user_id`, `email`.',
            self::UserUpdated => 'A user\'s profile changed. Payload: `user_id`, `changed` (the fields that changed).',
            self::UserDeactivated => 'A user was deactivated and can no longer sign in. Payload: `user_id`.',
            self::UserReactivated => 'A deactivated user was reactivated. Payload: `user_id`.',
            self::UserLogin => 'A user signed in through a federated (SSO) connection. Payload: `user_id`, `connection_id`.',
            self::IdentityLinked => 'An external identity (a social or enterprise login) was linked to a user. Payload: `user_id`, `provider`.',
            self::OrganizationCreated => 'An organization was created. Payload: `id`, `slug`.',
            self::OrganizationUpdated => 'An organization\'s name, slug or settings changed. Payload: `id`, `name`, `slug`, `changed` (which of `name`, `slug`, `settings`), and `settings_keys` for a settings change.',
            self::OrganizationSuspended => 'An organization was suspended; its members are refused until it is reactivated. Payload: `id`, `status`.',
            self::OrganizationReactivated => 'A suspended organization was reactivated. Payload: `id`, `status`.',
            self::OrganizationDeleted => 'An organization was archived — by an operator, or by its owner — and no longer grants access. Payload: `id`, `slug`, `status`.',
            self::OrganizationArchived => 'Legacy name for an archive; emitted alongside organization.deleted. Payload: `id`, `status`.',
            self::OrganizationSettingsUpdated => 'Legacy name for a settings change; emitted alongside organization.updated. Payload: `id`, `keys` (the settings keys written).',
            self::MembershipCreated => 'A person joined an organization — added directly or by accepting an invitation. Payload: `user_id`, `role`, `status`, `invited_by`.',
            self::MembershipUpdated => 'A member\'s tier in an organization changed. Payload: `user_id`, `role`, `previous_role`, `reason` (`role_changed` or `ownership_transferred`).',
            self::MembershipDeleted => 'A person stopped being a member of an organization, with every role they held there. Payload: `user_id`, `role` (the tier they had), `reason` (`removed` or `left`).',
            self::OrganizationMemberAdded => 'Legacy name for a new membership; emitted alongside membership.created. Payload: `user_id`, `role`.',
            self::OrganizationMemberRemoved => 'Legacy name for a removed membership; emitted alongside membership.deleted. Payload: `user_id`.',
            self::OrganizationMemberRoleChanged => 'Legacy name for a role change; emitted alongside membership.updated. Payload: `user_id`, `role`.',
            self::InvitationCreated => 'Somebody was invited to join an organization. Payload: `invitation_id`, `email`, `role`, `invited_by`, `expires_at`.',
            self::InvitationAccepted => 'An invitation was accepted and the membership created. Payload: `invitation_id`, `user_id`, `email`, `role`.',
            self::InvitationRevoked => 'A pending invitation stopped working — revoked, or superseded by a newer invitation to the same address. Payload: `invitation_id`, `email`, `reason` (`revoked` or `superseded`).',
            self::OrganizationInvitationCreated => 'Legacy name for a new invitation; emitted alongside invitation.created. Payload: `email`, `role`.',
            self::OrganizationInvitationAccepted => 'Legacy name for an accepted invitation; emitted alongside invitation.accepted. Payload: `user_id`.',
            self::RoleAssigned => 'A role was granted to a member in an organization. Payload: `user_id`, `role_id`.',
            self::RoleUnassigned => 'A role was taken away from a member in an organization — directly, or because the role was deleted. Payload: `user_id`, `role_id`.',
            self::RoleAssignedEverywhere => 'A role was granted to a user across the whole environment, in every organization. Payload: `user_id`, `role_id`.',
            self::RoleUnassignedEverywhere => 'An environment-wide role grant was taken away. Payload: `user_id`, `role_id`.',
            self::ApiKeyCreated => 'A customer API key was created for an app. Payload: the key id, `user_id`, `client_id`, its permissions and expiry — never the secret.',
            self::ApiKeyRevoked => 'A customer API key was revoked and stops verifying. Payload: the key id, `user_id`, `client_id`.',
            self::SupportSessionStarted => 'A staff member started a time-boxed support session acting for a user in one app. Payload: the actor, the target user, the app, the reason and the expiry.',
            self::DirectoryUserProvisioned => 'A user was created or updated by directory sync (SCIM).',
            self::DirectoryUserDeprovisioned => 'A user was deleted by directory sync (SCIM).',
            self::DirectoryUserDeactivated => 'A user was deactivated by directory sync (SCIM).',
            self::DirectoryGroupMembershipChanged => 'A directory group\'s members changed through directory sync (SCIM).',
            self::DomainAdded => 'A domain was added to an organization, pending DNS verification. Payload: `id`, `domain`.',
            self::DomainRemoved => 'A domain was removed from an organization. Payload: `id`, `domain`.',
            self::DomainVerified => 'A domain passed DNS verification and can route sign-ins to the organization\'s SSO. Payload: `id`, `domain`.',
            self::ConnectionActivated => 'An SSO connection went live (once, on the change). Payload: `id`, `type`, `provider`, `name`.',
            self::EntitlementSet => 'An entitlement was set for an organization for the first time. Payload: `key` and its value.',
            self::EntitlementUpdated => 'An organization\'s entitlement changed. Payload: `key` and its value.',
            self::EntitlementRevoked => 'An entitlement was removed from an organization. Payload: `key`.',
            self::VaultGrantCreated => 'An app was granted (or re-granted) leases of a token-vault secret. Payload: `secret_id`, `client_id`, `max_ttl_seconds` — never the credential.',
            self::VaultGrantRevoked => 'An app\'s grant to a token-vault secret was revoked. Payload: `secret_id`, `client_id`.',
            self::VaultSecretRevoked => 'A token-vault secret was revoked and can no longer be leased. Payload: `secret_id`, `provider`.',
            self::GovernanceAccessRevoked => 'An access review took a grant away when its campaign closed. Payload: `campaign_id`, `user_id`, `access_type`, `access_ref`.',
        };
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
            self::MembershipCreated => 'A member joined an organization',
            self::MembershipUpdated => 'A member\'s role changed',
            self::MembershipDeleted => 'A member left or was removed from an organization',
            self::InvitationCreated => 'An invitation was sent',
            self::InvitationAccepted => 'An invitation was accepted',
            self::InvitationRevoked => 'An invitation was revoked',
            self::OrganizationUpdated => 'An organization was updated',
            self::OrganizationDeleted => 'An organization was deleted',
            self::OrganizationArchived => 'An organization was archived',
            self::UserLogin => 'A user signed in',
            self::UserReactivated => 'A user was reactivated',
            self::IdentityLinked => 'An external identity was linked to a user',
            self::RoleUnassigned => 'A role was removed from a member',
            self::RoleAssignedEverywhere => 'A role was granted across the environment',
            self::RoleUnassignedEverywhere => 'An environment-wide role was removed',
            self::ApiKeyCreated => 'A customer API key was created',
            self::ApiKeyRevoked => 'A customer API key was revoked',
            self::SupportSessionStarted => 'Somebody started acting as a member (support session)',
        };
    }
}
