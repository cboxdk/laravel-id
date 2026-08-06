<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Contracts;

use Cbox\Id\Kernel\Authorization\ValueObjects\Relationship;

/**
 * The owned ReBAC relationship-tuple store. Right-sized: direct tuples plus
 * bounded, recursive userset expansion (groups/roles) over Postgres — no
 * external authorization service.
 */
interface RelationshipStore
{
    public function write(Relationship $relationship): void;

    public function delete(Relationship $relationship): void;

    /**
     * Does `subject` have `relation` on the object, directly or transitively via
     * usersets? Deny-by-default: returns false unless a grant path exists.
     */
    public function check(
        string $organizationId,
        string $objectType,
        string $objectId,
        string $relation,
        string $subjectType,
        string $subjectId,
    ): bool;
}
