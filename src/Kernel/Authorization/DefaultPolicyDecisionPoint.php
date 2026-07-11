<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\Contracts\RelationshipStore;
use Cbox\Id\Kernel\Authorization\ValueObjects\Decision;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Subject;

/**
 * Deny-by-default decision point over the relationship store and entitlement
 * projection. The only source of "allow" is an explicit relationship grant.
 */
final class DefaultPolicyDecisionPoint implements PolicyDecisionPoint
{
    public function __construct(
        private readonly RelationshipStore $relationships,
        private readonly EntitlementReader $entitlements,
    ) {}

    public function decide(string $organizationId, Subject $subject, string $relation, ResourceRef $resource): Decision
    {
        $granted = $this->relationships->check(
            $organizationId,
            $resource->type,
            $resource->id,
            $relation,
            $subject->type,
            $subject->id,
        );

        return $granted
            ? Decision::allow("relation:{$relation}")
            : Decision::deny();
    }

    public function can(string $organizationId, Subject $subject, string $relation, ResourceRef $resource): bool
    {
        return $this->decide($organizationId, $subject, $relation, $resource)->allowed;
    }

    public function entitlement(string $organizationId, string $key): ?EntitlementValue
    {
        return $this->entitlements->get($organizationId, $key);
    }
}
