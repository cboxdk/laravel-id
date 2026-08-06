<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;

/**
 * The default {@see SubjectGrantRevoker}: a subject's grants are their outstanding
 * refresh tokens. Living in OAuthServer (which already depends on Identity) keeps
 * Identity free of any OAuth import.
 */
class RefreshTokenGrantRevoker implements SubjectGrantRevoker
{
    public function __construct(private readonly RefreshTokens $refreshTokens) {}

    public function revokeGrantsForUser(string $userId): void
    {
        $this->refreshTokens->revokeForUser($userId);
    }
}
