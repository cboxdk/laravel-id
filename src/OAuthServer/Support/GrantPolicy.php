<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\OAuthServer\Models\Client;

/**
 * May this client use this grant?
 *
 * One place, so INITIATION and REDEMPTION cannot disagree. Enforcing only at redemption
 * let a client that may never complete a device or CIBA flow still create the state and
 * put a prompt in front of a user — unauthorized flow state and prompt spam, refused only
 * at the very end.
 */
class GrantPolicy
{
    public static function allows(Client $client, string $grantType): bool
    {
        $registered = $client->grant_types;

        if ($registered === []) {
            // Closed by default: a client that predates the field gets the one grant it
            // could plausibly have been registered for.
            return $grantType === 'authorization_code';
        }

        // refresh_token is implied by authorization_code — the code path mints one
        // whenever offline_access is granted, so refusing it here would issue a token
        // that can never be redeemed.
        if ($grantType === 'refresh_token' && in_array('authorization_code', $registered, true)) {
            return true;
        }

        return in_array($grantType, $registered, true);
    }
}
