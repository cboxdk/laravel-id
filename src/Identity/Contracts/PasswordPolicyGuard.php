<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\Exceptions\PolicyViolation;

/**
 * Applies the tenant's authentication policy to a proposed password.
 *
 * Every path that sets a credential goes through this, so a rule cannot be honoured on
 * self-service change but skipped on administrative assignment.
 */
interface PasswordPolicyGuard
{
    /**
     * Refuse a password that does not satisfy the effective policy — too short, found in
     * a breach corpus, or matching one the subject used recently.
     *
     * @throws PolicyViolation
     */
    public function assertAcceptable(string $password, ?string $userId = null, ?string $organizationId = null): void;

    /**
     * Retain a hash so future changes can be checked against it, keeping only as many as
     * the policy compares against. A no-op when reuse history is off.
     */
    public function remember(string $userId, string $passwordHash, ?string $organizationId = null): void;
}
