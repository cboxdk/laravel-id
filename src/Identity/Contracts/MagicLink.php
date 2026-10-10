<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\SignInMethodDisabled;
use Cbox\Id\Identity\Models\Session;

interface MagicLink
{
    /**
     * Issue a single-use login token for an email. Returns the raw token to send
     * (only its hash is stored).
     *
     * Refuses with {@see SignInMethodDisabled} where magic links are off ({@see SignInMethods}).
     */
    public function request(string $email): string;

    /**
     * Consume a token and start a session, provisioning the user on first login.
     * Throws if the token is unknown, expired or already used, and refuses with
     * {@see SignInMethodDisabled} where magic links are off — a link minted before they were
     * switched off included.
     */
    public function redeem(string $token): Session;
}
