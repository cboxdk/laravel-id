<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

/**
 * The organization tree, maintained as a transitive closure so ancestor/
 * descendant queries and transitive management checks are O(1) at any depth.
 */
interface OrganizationHierarchy
{
    /**
     * Register a node under an optional parent (null = root). Maintains the closure.
     */
    public function attach(string $organizationId, ?string $parentId): void;

    /**
     * @return list<string> strict descendant org ids, at any depth
     */
    public function descendants(string $organizationId): array;

    /**
     * @return list<string> strict ancestor org ids, at any depth
     */
    public function ancestors(string $organizationId): array;

    public function isDescendantOf(string $organizationId, string $ancestorId): bool;

    /**
     * Whether $managerId may manage $organizationId (itself, or an ancestor of it).
     * The transitive-access predicate the PDP uses for reseller/parent hierarchies.
     */
    public function manages(string $managerId, string $organizationId): bool;
}
