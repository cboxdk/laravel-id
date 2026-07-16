<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Usage\Enums;

use Cbox\Id\Kernel\Usage\Listeners\RecordUsageOnDomainEvent;

/**
 * The canonical, stable metric keys the platform meters. `record()` accepts any
 * string, but these are the first-party names a dashboard and future plan gates rely
 * on — keep them stable once shipped.
 *
 * Keys are namespaced `auth.*` to share one vocabulary with the billing side
 * (`cboxdk/cbox-billing` already meters `auth.login`, `auth.user`, `auth.id_token`),
 * so a local analytics counter and a billing meter of the same event agree. See
 * {@see RecordUsageOnDomainEvent} for the domain-event → metric mapping that drives
 * automatic recording.
 */
enum UsageMetric: string
{
    case Login = 'auth.login';
    case SessionStarted = 'auth.session';
    case UserCreated = 'auth.user';
    case IdTokenIssued = 'auth.id_token';
    case MfaEnrolled = 'auth.mfa_enrolled';
    case PasskeyRegistered = 'auth.passkey';
    case PasskeyAuthenticated = 'auth.passkey_auth';
    case OtpIssued = 'auth.otp';
    case IdentityLinked = 'auth.identity_linked';
    case OrganizationCreated = 'auth.organization';
    case MemberAdded = 'auth.member_added';
    case InvitationCreated = 'auth.invitation';
    case InvitationAccepted = 'auth.invitation_accepted';
    case RoleAssigned = 'auth.role_assigned';
    case ServiceAccountCreated = 'auth.service_account';
    case CibaRequested = 'auth.ciba';
    case DomainVerified = 'auth.domain_verified';
    case GovernanceCampaignOpened = 'auth.governance_campaign';
    case ScimSync = 'auth.scim_sync';
    case TokenLease = 'auth.vault_lease';
}
