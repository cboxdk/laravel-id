<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

use Cbox\Id\Organization\Exceptions\CustomerApiKeyRefused;

/**
 * Why a customer API key could not be issued ({@see CustomerApiKeyRefused}).
 *
 * Issuance is a management action the key's own holder (or an administrator acting for
 * them) performs, so the reason is reported — unlike verification, which answers every
 * failure with the same `active: false`.
 */
enum ApiKeyRefusal: string
{
    /** No client with that `client_id` in this environment. */
    case UnknownClient = 'unknown_client';

    /** The client has not declared an `api_key_prefix`, so it accepts no keys. */
    case KeysNotEnabled = 'keys_not_enabled';

    /** The holder has no active membership in the organization. */
    case NotAMember = 'not_a_member';

    /** The organization is suspended or archived. */
    case OrganizationInactive = 'organization_inactive';

    /** The holder's account is disabled or does not exist. */
    case HolderInactive = 'holder_inactive';

    /** A requested permission is not among the holder's current permissions for the app. */
    case PermissionNotHeld = 'permission_not_held';

    /** The requested expiry is not in the future. */
    case ExpiryInPast = 'expiry_in_past';

    /** A permission or the name is empty or too long. */
    case InvalidInput = 'invalid_input';
}
