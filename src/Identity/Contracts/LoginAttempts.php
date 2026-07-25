<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * Counts failed password attempts per SUBJECT and locks the account out at the tenant's
 * {@see AuthPolicy::$lockoutThreshold}.
 *
 * Distinct from the IP-keyed rate limiting the sign-in forms already do. A rate limiter
 * protects the SERVICE from a flood; a lockout protects one ACCOUNT from being guessed
 * at — an attacker spreading attempts across a botnet never trips an IP limit, and a
 * shared office NAT trips one without anyone being attacked at all.
 *
 * The counter keys on the subject, so a wrong password for an address that does not
 * exist can never be used to discover that it does not exist.
 */
interface LoginAttempts
{
    /** Whether the subject is currently locked out. */
    public function isLockedOut(string $subjectId, ?string $organizationId = null): bool;

    /**
     * Record a failed attempt. Returns true when this failure crossed the threshold —
     * i.e. the caller has just locked the account, and may want to say so.
     */
    public function recordFailure(string $subjectId, ?string $organizationId = null): bool;

    /** Clear the counter after a successful authentication. */
    public function clear(string $subjectId): void;
}
