<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Contracts;

use Cbox\Id\Kernel\Authorization\ValueObjects\Decision;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Subject;

/**
 * The single point where authorization decisions are made. Enforcement points
 * (gateway, app, Filament policies) call this; they never re-implement logic.
 * Deny-by-default throughout.
 */
interface PolicyDecisionPoint
{
    public function decide(string $organizationId, Subject $subject, string $relation, ResourceRef $resource): Decision;

    public function can(string $organizationId, Subject $subject, string $relation, ResourceRef $resource): bool;

    public function entitlement(string $organizationId, string $key): ?EntitlementValue;
}
