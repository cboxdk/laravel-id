<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\RefreshGrant;

interface RefreshTokens
{
    /**
     * Issue the first refresh token of a new rotation family for this grant.
     * Returns the raw token (only its hash is stored).
     *
     * @param  list<string>  $scopes
     */
    public function issue(Client $client, ?string $userId, ?string $organizationId, array $scopes, ?string $audience = null): string;

    /**
     * Rotate a presented refresh token: validate it, consume it, and mint its
     * successor in the same family. Presenting an already-consumed token is
     * treated as theft — the whole family is revoked and {@see InvalidGrant} is
     * thrown. Throws {@see InvalidGrant} for unknown/expired/revoked tokens or a
     * client mismatch.
     *
     * @throws InvalidGrant
     */
    public function rotate(string $clientId, string $rawToken): RefreshGrant;

    /**
     * Revoke every refresh token in the family a given raw token belongs to
     * (e.g. on logout). No-op if the token is unknown.
     */
    public function revoke(string $rawToken): void;
}
