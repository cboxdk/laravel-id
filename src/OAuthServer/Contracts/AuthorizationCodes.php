<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\ValueObjects\ActingParty;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;

interface AuthorizationCodes
{
    /**
     * Issue a single-use code bound to the client, user, redirect URI and PKCE
     * challenge. Returns the raw code (only its hash is stored).
     *
     * Pass `$sessionId` — the {@see SessionManager} session the person approved from —
     * and the ID Token carries `sid`, and the session is recorded against the client so
     * ending it notifies the client (OIDC Back-Channel Logout 1.0). Without it the grant
     * works exactly as before and the client is only reachable by `sub`.
     *
     * `$actor` is set only for a support session's code ({@see SupportSessions}): the
     * grant it redeems into is then minted with `act`, no refresh token, and a lifetime
     * capped at the session's. Every ordinary code leaves it null.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $amr  authentication methods used at login
     */
    public function issue(
        string $clientId,
        string $userId,
        ?string $organizationId,
        string $redirectUri,
        array $scopes,
        string $codeChallenge,
        string $codeChallengeMethod = 'S256',
        ?string $nonce = null,
        ?int $authTime = null,
        array $amr = [],
        ?string $resource = null,
        ?string $sessionId = null,
        ?ActingParty $actor = null,
    ): string;

    /**
     * Exchange a code for its grant, enforcing single-use, expiry, redirect-URI
     * match and PKCE (S256). Throws {@see InvalidGrant} on any failure.
     */
    public function exchange(string $clientId, string $code, string $redirectUri, string $codeVerifier): AuthorizedGrant;
}
