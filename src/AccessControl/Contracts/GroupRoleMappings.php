<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Models\GroupRoleMapping;

/**
 * Maps customer directory groups onto Cbox ID roles, and reconciles the resulting
 * `pushed` role assignments as membership changes — the bridge from SCIM/directory
 * groups to roles. The directory says who is in a group; a mapping says what that
 * grants; reconciliation keeps the derived assignments in sync without ever touching
 * a manually-granted role.
 */
interface GroupRoleMappings
{
    public function map(string $organizationId, string $groupId, string $roleId, int $priority = 0): GroupRoleMapping;

    public function unmap(string $organizationId, string $groupId, string $roleId): void;

    /**
     * @return list<GroupRoleMapping>
     */
    public function forOrganization(string $organizationId): array;

    /**
     * Reconcile ONE user's group-derived (`pushed`) role assignments in an org to
     * match the roles mapped from the groups they currently belong to: grant newly-
     * mapped roles, revoke pushed roles no longer mapped, and never disturb a manual
     * or system assignment.
     */
    public function reconcileUser(string $organizationId, string $userId): void;

    /**
     * Reconcile everyone a directory group affects — its current members AND anyone
     * still holding a role it maps (so removals and deletions revoke correctly).
     * Call after the group's membership or its mappings change. `organizationId` is
     * supplied when the group row is already gone (a delete).
     */
    public function reconcileGroup(string $groupId, ?string $organizationId = null): void;
}
