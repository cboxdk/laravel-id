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

    /**
     * Every override for a set of organizations, in one read.
     *
     * The single-organization form is called in a LOOP on the hot path — password
     * expiry and the MFA mandate both walk the signed-in subject's memberships, from the
     * host's authentication middleware, on every request. Memoising it removed the
     * duplicate reads but not the shape: a subject in nine organizations still cost nine
     * queries per request, and the console's Sign-in rules page pays it once per
     * organization in the whole environment, unpaginated.
     *
     * Returns only the organizations that HAVE an override, so a caller distinguishes
     * "no override" by absence and never mistakes it for "not looked up".
     *
     * @param  list<string>  $organizationIds
     * @return array<string, AuthPolicy> keyed by organization id
     */
    public function overridesFor(array $organizationIds): array;

    /** Store (or replace) the environment baseline. */
    public function setForEnvironment(AuthPolicy $policy): void;

    /** Store (or replace) an organization's override. */
    public function setForOrganization(string $organizationId, AuthPolicy $policy): void;

    /** Drop an organization's override so it inherits the environment baseline again. */
    public function clearForOrganization(string $organizationId): void;
}
