<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Contracts;

use Cbox\Id\Governance\Exceptions\UnknownSodPolicy;
use Cbox\Id\Governance\Models\SodPolicy;
use Cbox\Id\Governance\ValueObjects\SodViolation;
use Cbox\Id\Kernel\Authorization\ValueObjects\Decision;

/**
 * Segregation of Duties: policies that forbid toxic combinations of roles, plus a
 * pre-grant gate the host calls BEFORE assigning a role, and a detector for
 * violations that already exist.
 *
 * The gate returns a reasoned {@see Decision} (the same allow/deny value object the
 * authorization PDP uses), so a refusal is auditable and carries the offending
 * policy. Deny-by-default is NOT assumed here — SoD only denies a proposed grant
 * that would actually complete a forbidden combination; anything else is allowed.
 *
 * Evaluation considers a subject's DIRECT role assignments at the organization
 * (consistent with where a grant is made and revoked); conflicts arising purely
 * from hierarchy-inherited roles are out of scope for v1.
 */
interface SegregationOfDuties
{
    /**
     * Define a policy over a mutually-exclusive set of role ids (holding ≥2 of them
     * at once is a violation). `organizationId` null = an environment-wide policy.
     *
     * @param  list<string>  $roleIds
     */
    public function definePolicy(?string $organizationId, string $name, array $roleIds, ?string $description = null): SodPolicy;

    /**
     * Activate or deactivate a policy (inactive policies are ignored by the gate and
     * the detector).
     *
     * UNSCOPED — it will toggle an ENVIRONMENT-WIDE policy, so it belongs to the
     * environment/operator control plane. A per-organization console must use
     * {@see setActiveForOrganization()} instead.
     *
     * @throws UnknownSodPolicy
     */
    public function setActive(string $policyId, bool $active): void;

    /**
     * Activate or deactivate a policy an organization OWNS. The policy must be scoped
     * to `$organizationId`; an environment-wide policy (organization_id null) or
     * another org's is refused with {@see UnknownSodPolicy}.
     *
     * This exists because an environment-wide policy is the control plane's own
     * toxic-combination rule and applies to every tenant: an org admin who could
     * deactivate it could then grant themselves the conflicting pair. Asserting
     * ownership in the framework means the check cannot be forgotten by a host's UI.
     *
     * @throws UnknownSodPolicy
     */
    public function setActiveForOrganization(string $organizationId, string $policyId, bool $active): void;

    /**
     * The pre-grant gate: would assigning `proposedRoleId` to the subject at this org
     * complete a forbidden combination? Returns a reasoned decision — deny carries
     * `sod:{policyId}` and the roles in conflict.
     */
    public function evaluate(string $organizationId, string $subjectId, string $proposedRoleId): Decision;

    /**
     * Boolean convenience over {@see evaluate()} — true when the proposed grant would
     * violate an active policy.
     */
    public function wouldViolate(string $organizationId, string $subjectId, string $proposedRoleId): bool;

    /**
     * The SoD violations a subject ALREADY has at this organization.
     *
     * @return list<SodViolation>
     */
    public function violationsFor(string $organizationId, string $subjectId): array;

    /**
     * Every SoD violation across all subjects at this organization (a governance
     * report; can seed a certification campaign).
     *
     * @return list<SodViolation>
     */
    public function scan(string $organizationId): array;
}
