<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * Why a support session could not be started, or a code for it minted.
 *
 * An enum so a caller (and a test) can tell the refusals apart without matching message
 * text, and so every refusal has exactly one wording.
 */
enum SupportSessionRefusal: string
{
    case ReasonRequired = 'reason_required';
    case SelfImpersonation = 'self_impersonation';
    case UnknownClient = 'unknown_client';
    case ClientNotEligible = 'client_not_eligible';
    case NoRedirectUri = 'no_redirect_uri';
    case RedirectUriNotRegistered = 'redirect_uri_not_registered';
    case OrganizationInactive = 'organization_inactive';
    case TargetNotMember = 'target_not_member';
    case NotPermitted = 'not_permitted';
    case SessionNotActive = 'session_not_active';

    public function message(): string
    {
        return match ($this) {
            self::ReasonRequired => 'A support session needs a reason.',
            self::SelfImpersonation => 'A support session cannot target the person starting it.',
            self::UnknownClient => 'The application does not exist in this environment.',
            self::ClientNotEligible => 'Support sessions are only available for first-party applications the environment owns that use the authorization code grant.',
            self::NoRedirectUri => 'The application has no registered redirect URI to complete a sign-in on.',
            self::RedirectUriNotRegistered => 'The redirect URI is not registered for this application.',
            self::OrganizationInactive => 'The organization is not active.',
            self::TargetNotMember => 'The person is not an active member of the organization.',
            self::NotPermitted => 'The actor does not hold support:impersonate for this application environment-wide.',
            self::SessionNotActive => 'The support session has ended or expired, or belongs to somebody else.',
        };
    }
}
