<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Models\Session;

interface MagicLink
{
    /**
     * Issue a single-use login token for an email. Returns the raw token to send
     * (only its hash is stored).
     */
    public function request(string $email): string;

    /**
     * Consume a token and start a session, provisioning the user on first login.
     * Throws if the token is unknown, expired or already used.
     */
    public function redeem(string $token): Session;
}
