<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;

interface AuthorizationCodes
{
    /**
     * Issue a single-use code bound to the client, user, redirect URI and PKCE
     * challenge. Returns the raw code (only its hash is stored).
     *
     * @param  list<string>  $scopes
     */
    public function issue(
        string $clientId,
        string $userId,
        ?string $organizationId,
        string $redirectUri,
        array $scopes,
        string $codeChallenge,
        string $codeChallengeMethod = 'S256',
    ): string;

    /**
     * Exchange a code for its grant, enforcing single-use, expiry, redirect-URI
     * match and PKCE (S256). Throws {@see InvalidGrant} on any failure.
     */
    public function exchange(string $clientId, string $code, string $redirectUri, string $codeVerifier): AuthorizedGrant;
}
