<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\InvalidPasswordReset;

interface PasswordReset
{
    /**
     * Issue a single-use reset token for an email, but only if an account exists.
     * Returns the raw token to email, or null when no account matches — the caller
     * MUST show the same response either way, so the endpoint never reveals whether
     * an address is registered (anti-enumeration).
     */
    public function request(string $email): ?string;

    /**
     * Consume a token and set the new password. Every existing session for the
     * account is revoked, since a reset implies the old credential is compromised.
     * Throws {@see InvalidPasswordReset} if the token
     * is unknown, expired or already used.
     */
    public function reset(string $token, string $newPassword): void;
}
