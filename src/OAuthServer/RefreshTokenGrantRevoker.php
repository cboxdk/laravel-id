<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Models\AccessToken;

/**
 * The default {@see SubjectGrantRevoker}: a subject's grants are their outstanding
 * refresh tokens AND the access tokens already minted from them. Living in OAuthServer
 * (which already depends on Identity) keeps Identity free of any OAuth import.
 */
class RefreshTokenGrantRevoker implements SubjectGrantRevoker
{
    public function __construct(private readonly RefreshTokens $refreshTokens) {}

    public function revokeGrantsForUser(string $userId): void
    {
        $this->refreshTokens->revokeForUser($userId);

        // AND THE ACCESS TOKENS ALREADY IN FLIGHT. Cutting the refresh grant stops the
        // renewal and leaves everything already minted valid until it expires — and
        // introspection, which is what UserInfo, the decisions endpoint, the frontend
        // session endpoint and token exchange all ask, only checks whether the row is
        // revoked. So the row is what has to change.
        AccessToken::query()
            ->where('user_id', $userId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }
}
