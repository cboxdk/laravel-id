<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * Answers whether a subject's password has outlived the tenant's
 * {@see AuthPolicy::$maxAgeDays}.
 *
 * A max age is only meaningful if something acts on it, and something acting on it needs
 * to know when the password was last set — which the host-owned users table cannot be
 * relied on to record. The platform keeps its own timestamp, stamped by the credential
 * primitive, and this is the question asked of it.
 */
interface PasswordExpiry
{
    /** Stamp the subject's password as set right now. Idempotent per subject. */
    public function record(string $subjectId): void;

    /**
     * Whether the subject must choose a new password because the old one is too old.
     *
     * False when the policy sets no maximum age, and false when the platform has no
     * record of when the password was set — a subject whose credential predates this
     * being tracked is not evidence of an OLD password, and locking them out on that
     * assumption would be a worse failure than letting the clock start late.
     */
    public function hasExpired(string $subjectId, ?string $organizationId = null): bool;
}
