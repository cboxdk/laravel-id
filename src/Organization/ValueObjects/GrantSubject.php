<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\ValueObjects;

use Cbox\Id\Organization\GroupService;

/**
 * Who receives a resource grant — a user directly, or a group (in which case
 * every member inherits the grant through userset expansion).
 */
readonly class GrantSubject
{
    private function __construct(
        public string $type,
        public string $id,
    ) {}

    public static function user(string $id): self
    {
        return new self('user', $id);
    }

    public static function group(string $groupId): self
    {
        return new self(GroupService::OBJECT_TYPE, $groupId);
    }

    public function isGroup(): bool
    {
        return $this->type === GroupService::OBJECT_TYPE;
    }

    /**
     * The tuple's subject_relation: a user is a direct subject; a group grant
     * targets the group's members userset.
     */
    public function subjectRelation(): ?string
    {
        return $this->isGroup() ? GroupService::MEMBER_RELATION : null;
    }
}
