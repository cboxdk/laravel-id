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
     * The subject is REQUIRED, and deliberately has no default. It used to be optional,
     * and passing nothing quietly bought a weaker check: no reuse history, and the bare
     * environment baseline instead of the organizations that bind the subject. An
     * exemption a caller can reach by forgetting an argument is one that looks identical
     * to the case where it is correct — see {@see assertAcceptableForNewSubject()}, which
     * is that case, named.
     *
     * @throws PolicyViolation
     */
    public function assertAcceptable(string $password, string $userId, ?string $organizationId = null): void;

    /**
     * The same rules for a subject that does not exist yet — signup, or an administrator
     * seeding an account.
     *
     * Length and the breach corpus bind exactly as they do later. Reuse history cannot:
     * there is no history, because there is no subject. Callers state that by choosing
     * this method rather than by omitting an argument.
     *
     * @throws PolicyViolation
     */
    public function assertAcceptableForNewSubject(string $password, ?string $organizationId = null): void;

    /**
     * Retain a hash so future changes can be checked against it, keeping only as many as
     * the policy compares against. A no-op when reuse history is off.
     */
    public function remember(string $userId, string $passwordHash, ?string $organizationId = null): void;
}
