<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Contracts;

use Cbox\Id\Organization\Models\UserGroup;
use Illuminate\Database\Eloquent\Collection;

/**
 * Organization-local user groups. Groups exist to be grant subjects: give a
 * group a role on a resource and every member inherits it (highest role wins
 * in effective-access resolution).
 */
interface Groups
{
    public function create(string $organizationId, string $name): UserGroup;

    /**
     * Deletes the group, its memberships, and every grant where the group is
     * the subject — a deleted group must never leave dangling access behind.
     */
    public function delete(string $organizationId, string $groupId): void;

    public function addMember(string $organizationId, string $groupId, string $userId): void;

    public function removeMember(string $organizationId, string $groupId, string $userId): void;

    /**
     * User ids of the group's members.
     *
     * @return list<string>
     */
    public function members(string $organizationId, string $groupId): array;

    /**
     * Groups the user belongs to within the organization.
     *
     * @return Collection<int, UserGroup>
     */
    public function groupsFor(string $organizationId, string $userId): Collection;

    /**
     * @return Collection<int, UserGroup>
     */
    public function forOrganization(string $organizationId): Collection;
}
