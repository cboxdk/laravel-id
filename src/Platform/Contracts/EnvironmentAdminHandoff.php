<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Contracts;

use Cbox\Id\Platform\ValueObjects\EnvironmentAdminGrant;

/**
 * Mints and verifies the signed handoff that carries a control-plane identity from the
 * ACCOUNT plane (cboxid.com) into a tenant ENVIRONMENT's admin console without a
 * second login. The token is platform-signed (managed keys, algorithm-pinned on
 * verify) and short-lived, so it is single-purpose proof of "this account member
 * may administer this environment" — never a general session credential, and never
 * accepted for anything but establishing an environment-admin session.
 *
 * This is what keeps the tenant admin a control-plane identity: the target environment
 * never stores an admin subject; it trusts the platform's signature instead.
 */
interface EnvironmentAdminHandoff
{
    /**
     * Mint a short-lived signed handoff token binding a PLATFORM-ROOT SUBJECT to an
     * environment. TTL is deliberately tiny (seconds) — it is redeemed immediately
     * on the redirect to the environment host.
     *
     * The subject, not the account membership, because the subject is the credential of
     * record: the membership and its capability gate are re-resolved on redemption and
     * on every request thereafter, so the token can never outlive the access it implies.
     */
    public function mint(string $subjectId, string $environmentId, int $ttlSeconds = 120): string;

    /**
     * Verify a presented token: signature, expiry, pinned algorithm and purpose.
     * Returns the grant, or null for anything invalid, expired, or not a handoff
     * token — the caller learns nothing more than "not valid".
     */
    public function verify(string $token): ?EnvironmentAdminGrant;
}
