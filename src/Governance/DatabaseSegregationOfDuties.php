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
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Support\Str;

/**
 * Database-backed {@see SegregationOfDuties}. A policy names a set of roles that are
 * mutually exclusive; holding two or more at once is a conflict. Evaluation looks at
 * a subject's DIRECT role assignments at the organization (via the {@see Roles}
 * read surface), so it acts on exactly the grants that are made and revoked there.
 */
class DatabaseSegregationOfDuties implements SegregationOfDuties
{
    public function __construct(
        private readonly Roles $roles,
        private readonly AuditLog $audit,
        private readonly EnvironmentContext $environments,
    ) {}

    public function definePolicy(?string $organizationId, string $name, array $roleIds, ?string $description = null): SodPolicy
    {
        $this->environments->requireEnvironment();

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
        $this->environments->requireEnvironment();

        $policy = SodPolicy::query()->whereKey($policyId)->first();

        if ($policy === null) {
            throw UnknownSodPolicy::forId($policyId);
        }

        $policy->active = $active;
        $policy->save();
    }

    public function evaluate(string $organizationId, string $subjectId, string $proposedRoleId): Decision
    {
        $this->environments->requireEnvironment();

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
        $this->environments->requireEnvironment();

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

    public function scan(string $organizationId): array
    {
        $this->environments->requireEnvironment();

        $subjectIds = array_values(array_unique(array_map(
            static fn (RoleAssignment $a): string => $a->user_id,
            $this->roles->assignmentsInOrganization($organizationId),
        )));

        $violations = [];

        foreach ($subjectIds as $subjectId) {
            foreach ($this->violationsFor($organizationId, $subjectId) as $violation) {
                $violations[] = $violation;
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
