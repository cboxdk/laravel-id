<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * A relationship tuple (Zanzibar-style), scoped to a tenant.
 *
 *   (object_type:object_id) # relation @ (subject_type:subject_id[#subject_relation])
 *
 * A null `subjectRelation` is a direct grant. A non-null one is a userset: e.g.
 * "members of group:eng are viewers of doc:1" =
 *   new Relationship('org', 'doc', '1', 'viewer', 'group', 'eng', 'member').
 */
final readonly class Relationship
{
    public function __construct(
        public string $organizationId,
        public string $objectType,
        public string $objectId,
        public string $relation,
        public string $subjectType,
        public string $subjectId,
        public ?string $subjectRelation = null,
    ) {}
}
