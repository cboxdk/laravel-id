<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;

/**
 * Mints the Logout Token of Back-Channel Logout 1.0 §2.4 — a JWT signed with the
 * environment's key, exactly like an ID Token, so a relying party verifies both against
 * the same JWKS.
 */
interface LogoutTokenIssuer
{
    public function issue(Client $client, LogoutNotice $notice): string;
}
