<?php

declare(strict_types=1);

namespace Cbox\Id\Governance;

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Cbox\Id\Governance\Exceptions\UnknownSodPolicy;
use Cbox\Id\Governance\Models\SodPolicy;
use Cbox\Id\Governance\ValueObjects\SodViolation;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Authorization\ValueObjects\Decision;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Illuminate\Support\Str;

/**
 * Database-backed {@see SegregationOfDuties}. A policy names a set of roles that are
 * mutually exclusive; holding two or more at once is a conflict. Evaluation looks at
 * a subject's DIRECT role assignments at the organization (via the {@see Roles}
 * read surface), so it acts on exactly the grants that are made and revoked there.
 */
class DatabaseSegregationOfDuties implements SegregationOfDuties
{
    // Lazy per-call resolution of the ambient environment. This class is a `singleton`
    // (GovernanceServiceProvider) and EnvironmentContext is `scoped`, so injecting it here
    // would pin a queue worker to the first job's environment for the life of the process.
    use ResolvesEnvironment;

    public function __construct(
        private readonly Roles $roles,
        private readonly AuditLog $audit,
    ) {}

    public function definePolicy(?string $organizationId, string $name, array $roleIds, ?string $description = null): SodPolicy
    {
        $this->environments()->requireEnvironment();

        $policy = new SodPolicy;
        $policy->id = (string) Str::ulid();
        $policy->fill([
            'organization_id' => $organizationId,
            'name' => $name,
            'description' => $description,
            'active' => true,
            'role_ids' => array_values(array_unique($roleIds)),
        ]);
        $policy->save();

        $this->audit->record(new AuditEvent(
            action: 'sod.policy_defined',
            actorType: ActorType::System,
            organizationId: $organizationId,
            targetType: 'sod_policy',
            targetId: $policy->id,
            context: ['name' => $name, 'role_ids' => $policy->role_ids],
        ));

        return $policy;
    }

    public function setActive(string $policyId, bool $active): void
    {
        $this->toggle($policyId, $active, null);
    }

    public function setActiveForOrganization(string $organizationId, string $policyId, bool $active): void
    {
        $this->toggle($policyId, $active, $organizationId);
    }

    /**
     * @param  string|null  $owningOrganizationId  when given, the policy MUST be scoped to that
     *                                             org — an environment-wide policy is not the org's to disable
     */
    private function toggle(string $policyId, bool $active, ?string $owningOrganizationId): void
    {
        $this->environments()->requireEnvironment();

        $policy = SodPolicy::query()->whereKey($policyId)->first();

        if ($policy === null) {
            throw UnknownSodPolicy::forId($policyId);
        }

        // Refused as "unknown" rather than "forbidden": an org admin should not be able
        // to probe for the existence of another scope's policies.
        if ($owningOrganizationId !== null && $policy->organization_id !== $owningOrganizationId) {
            throw UnknownSodPolicy::forId($policyId);
        }

        $policy->active = $active;
        $policy->save();

        // A control that can be switched off is a control whose switching must be on
        // the record — the audit trail previously showed the policy being DEFINED and
        // nothing at all when it was disabled.
        $this->audit->record(new AuditEvent(
            action: $active ? 'sod.policy_activated' : 'sod.policy_deactivated',
            actorType: ActorType::System,
            organizationId: $policy->organization_id,
            targetType: 'sod_policy',
            targetId: $policy->id,
            context: ['name' => $policy->name],
        ));
    }

    public function evaluate(string $organizationId, string $subjectId, string $proposedRoleId): Decision
    {
        $this->environments()->requireEnvironment();

        $held = $this->heldRoleIds($organizationId, $subjectId);

        foreach ($this->applicablePolicies($organizationId) as $policy) {
            // Only policies that govern the proposed role can be tripped by it.
            if (! in_array($proposedRoleId, $policy->role_ids, true)) {
                continue;
            }

            // Any OTHER role in the set the subject already holds completes the
            // forbidden combination.
            $alreadyInSet = array_values(array_intersect($policy->role_ids, $held));
            $others = array_values(array_diff($alreadyInSet, [$proposedRoleId]));

            if ($others !== []) {
                return Decision::deny('sod:'.$policy->id);
            }
        }

        return Decision::allow('sod:no-conflict');
    }

    public function wouldViolate(string $organizationId, string $subjectId, string $proposedRoleId): bool
    {
        return ! $this->evaluate($organizationId, $subjectId, $proposedRoleId)->allowed;
    }

    public function violationsFor(string $organizationId, string $subjectId): array
    {
        $this->environments()->requireEnvironment();

        $held = $this->heldRoleIds($organizationId, $subjectId);
        $violations = [];

        foreach ($this->applicablePolicies($organizationId) as $policy) {
            $inConflict = array_values(array_intersect($policy->role_ids, $held));

            // Two or more roles from a mutually-exclusive set held at once = a violation.
            if (count($inConflict) >= 2) {
                $violations[] = new SodViolation(
                    policyId: $policy->id,
                    policyName: $policy->name,
                    subjectId: $subjectId,
                    organizationId: $organizationId,
                    conflictingRoleIds: $inConflict,
                );
            }
        }

        return $violations;
    }

    /**
     * Every violation in an organization, in TWO queries rather than two per person.
     *
     * This used to read the organization's assignments, reduce them to the distinct
     * subjects, and then call {@see violationsFor()} for each — and that method asks for
     * the subject's assignments and for the applicable policies itself. A scan of an
     * organization where five thousand people hold a role was ten thousand queries, on a
     * console page whose search box re-ran it on every debounced keystroke.
     *
     * Both reads are hoisted. The assignments are already in the first one, and the
     * policy set is identical for every subject in the organization by construction —
     * the query asks for this organization's policies plus the environment-wide ones,
     * neither of which varies by person. What is left per subject is the array
     * intersection it always was.
     */
    public function scan(string $organizationId): array
    {
        $this->environments()->requireEnvironment();

        /** @var array<string, list<string>> $heldBySubject */
        $heldBySubject = [];

        foreach ($this->roles->assignmentsInOrganization($organizationId) as $assignment) {
            $heldBySubject[$assignment->user_id][] = $assignment->role_id;
        }

        $policies = $this->applicablePolicies($organizationId);
        $violations = [];

        foreach ($heldBySubject as $subjectId => $held) {
            foreach ($policies as $policy) {
                $inConflict = array_values(array_intersect($policy->role_ids, $held));

                // Two or more roles from a mutually-exclusive set held at once.
                if (count($inConflict) >= 2) {
                    $violations[] = new SodViolation(
                        policyId: $policy->id,
                        policyName: $policy->name,
                        subjectId: (string) $subjectId,
                        organizationId: $organizationId,
                        conflictingRoleIds: $inConflict,
                    );
                }
            }
        }

        return $violations;
    }

    /**
     * @return list<string>
     */
    private function heldRoleIds(string $organizationId, string $subjectId): array
    {
        return array_map(
            static fn (RoleAssignment $a): string => $a->role_id,
            $this->roles->assignmentsForSubject($organizationId, $subjectId),
        );
    }

    /**
     * Active policies that govern this org: an org-specific policy plus every
     * environment-wide (null-org) one.
     *
     * @return list<SodPolicy>
     */
    private function applicablePolicies(string $organizationId): array
    {
        return array_values(SodPolicy::query()
            ->where('active', true)
            ->where(function ($query) use ($organizationId): void {
                $query->whereNull('organization_id')->orWhere('organization_id', $organizationId);
            })
            ->get()
            ->all());
    }
}
