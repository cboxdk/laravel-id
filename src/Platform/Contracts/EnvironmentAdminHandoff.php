<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\ValueObjects\EnvironmentAdminGrant;

/**
 * Mints and verifies the signed handoff that carries an account member from the
 * ACCOUNT plane (cboxid.com) into a tenant ENVIRONMENT's admin console without a
 * second login. The token is platform-signed (managed keys, algorithm-pinned on
 * verify) and short-lived, so it is single-purpose proof of "this account member
 * may administer this environment" — never a general session credential, and never
 * accepted for anything but establishing an environment-admin session.
 *
 * This is what keeps the tenant admin an account-layer identity: the environment
 * never stores an admin subject; it trusts the platform's signature instead.
 */
interface EnvironmentAdminHandoff
{
    /**
     * Mint a short-lived signed handoff token binding an account member to an
     * environment. TTL is deliberately tiny (seconds) — it is redeemed immediately
     * on the redirect to the environment host.
     */
    public function mint(string $accountMemberId, string $environmentId, int $ttlSeconds = 120): string;

    /**
     * Verify a presented token: signature, expiry, pinned algorithm and purpose.
     * Returns the grant, or null for anything invalid, expired, or not a handoff
     * token — the caller learns nothing more than "not valid".
     */
    public function verify(string $token): ?EnvironmentAdminGrant;
}
