<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\JwtTokenIssuer;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;

/**
 * A {@see TokenIssuer} that can put the login behind a grant on the access token —
 * `auth_time` and `acr` (RFC 9470 §6.1) — so a resource server can demand a recent or
 * stronger authentication without a round trip.
 *
 * A SEPARATE CONTRACT rather than a new parameter on {@see TokenIssuer::issueForUser()},
 * because hosts implement that interface and adding to it would break them. The token
 * endpoint asks whether the bound issuer is also one of these; a host's own issuer that is
 * not keeps working exactly as before, its tokens simply carry no authentication context
 * (and a resource server requiring one will refuse them, which is the fail-closed answer).
 * {@see JwtTokenIssuer} implements both.
 */
interface AuthenticationAwareTokenIssuer extends TokenIssuer
{
    /**
     * {@see TokenIssuer::issueForUser()}, plus the authentication the grant descends from.
     *
     * Called for the grants that HAVE one — authorization code, its refreshes, CIBA —
     * and never for `client_credentials`, which has no person behind it. `acr` is derived
     * from the event's `amr`, never from what was requested.
     *
     * @param  list<string>  $scopes
     */
    public function issueForAuthenticatedUser(
        Client $client,
        string $userId,
        ?string $organizationId,
        array $scopes,
        AuthenticationEvent $authentication,
        ?string $resource = null,
        ?string $dpopJkt = null,
    ): IssuedToken;
}
