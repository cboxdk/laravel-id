<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * Resolves the authentication rules in force for a tenant, and stores them.
 *
 * The ENVIRONMENT is the baseline every organization inherits; an organization's own
 * policy is layered on top and may only tighten it. Callers ask for the effective
 * policy and get one answer — they never combine the two levels themselves.
 */
interface AuthPolicies
{
    /**
     * The effective policy for an organization within the current environment: the
     * environment baseline tightened by the organization's override, if any. Passing
     * null asks for the environment baseline alone.
     */
    public function resolve(?string $organizationId = null): AuthPolicy;

    /** The environment's own baseline, ignoring any organization override. */
    public function forEnvironment(): AuthPolicy;

    /** The organization's stored override, or null when it inherits wholesale. */
    public function overrideFor(string $organizationId): ?AuthPolicy;

    /** Store (or replace) the environment baseline. */
    public function setForEnvironment(AuthPolicy $policy): void;

    /** Store (or replace) an organization's override. */
    public function setForOrganization(string $organizationId, AuthPolicy $policy): void;

    /** Drop an organization's override so it inherits the environment baseline again. */
    public function clearForOrganization(string $organizationId): void;
}
