<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\ValueObjects;

/**
 * A detected Segregation-of-Duties conflict: a subject holds (or would hold) two or
 * more roles that a policy declares mutually exclusive.
 */
final readonly class SodViolation
{
    /**
     * @param  list<string>  $conflictingRoleIds  the ≥2 policy roles the subject holds
     */
    public function __construct(
        public string $policyId,
        public string $policyName,
        public string $subjectId,
        public string $organizationId,
        public array $conflictingRoleIds,
    ) {}
}
