<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Testing;

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Organization\Contracts\Groups;
use Cbox\Id\Organization\Contracts\ResourceAccess;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\UserGroup;
use Cbox\Id\Organization\ValueObjects\GrantSubject;

/**
 * Convenience for groups, grants, and effective-role assertions in tests:
 *
 *     $group = $this->makeGroup($org->id, 'Engineering', members: ['user_1']);
 *     $this->grantAccess($org->id, GrantSubject::group($group->id), MembershipRole::Developer, ResourceRef::of('project', 'p1'));
 *     expect($this->effectiveRole($org->id, 'user_1', ResourceRef::of('project', 'p1')))->toBe(MembershipRole::Developer);
 */
trait InteractsWithAccess
{
    /**
     * @param  list<string>  $members
     */
    protected function makeGroup(string $organizationId, string $name, array $members = []): UserGroup
    {
        $groups = app(Groups::class);
        $group = $groups->create($organizationId, $name);

        foreach ($members as $userId) {
            $groups->addMember($organizationId, $group->id, $userId);
        }

        return $group;
    }

    protected function grantAccess(string $organizationId, GrantSubject $subject, MembershipRole $role, ResourceRef $resource): void
    {
        app(ResourceAccess::class)->grant($organizationId, $subject, $role, $resource);
    }

    protected function effectiveRole(string $organizationId, string $userId, ResourceRef ...$resources): ?MembershipRole
    {
        return app(ResourceAccess::class)->effectiveRole($organizationId, $userId, ...$resources);
    }
}
