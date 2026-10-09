<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * Which stored tuples to list: every field given must match exactly; none given lists
 * the environment's whole set. `subjectRelation` '' asks for direct subjects only.
 */
final readonly class TupleFilter
{
    public function __construct(
        public ?string $resourceType = null,
        public ?string $resourceId = null,
        public ?string $relation = null,
        public ?string $subjectType = null,
        public ?string $subjectId = null,
        public ?string $subjectRelation = null,
    ) {}
}
