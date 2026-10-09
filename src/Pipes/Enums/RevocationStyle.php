<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Enums;

/**
 * How a provider takes a token back.
 *
 * There is a standard for this (RFC 7009) and about half the catalogue follows it. The
 * others each invented their own, and a disconnect that only forgets the token locally
 * while the provider keeps honouring it is exactly the gap a "disconnect" button promises
 * to close — so each shape is named here instead of being approximated by the standard.
 */
enum RevocationStyle: string
{
    /**
     * RFC 7009: POST `token=<token>` form-encoded, with the client authenticating the
     * way the token endpoint expects. Google and Salesforce.
     */
    case Rfc7009 = 'rfc7009';

    /**
     * POST to the endpoint with the access token as the bearer credential and no body
     * worth speaking of. Slack's `auth.revoke` and Linear's `/oauth/revoke`.
     */
    case BearerToken = 'bearer_token';

    /**
     * GitHub: DELETE `/applications/{client_id}/grant` authenticated with the app's own
     * client id and secret (HTTP Basic), naming the access token in a JSON body. Revokes
     * the whole authorization, which is what "disconnect" means.
     */
    case GitHubGrant = 'github_grant';

    /**
     * HubSpot: DELETE with the refresh token in the PATH. No body, no client auth.
     */
    case RefreshTokenInPath = 'refresh_token_in_path';
}
