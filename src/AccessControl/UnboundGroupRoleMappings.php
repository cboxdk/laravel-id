<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Exceptions\ExternalRbacNotBound;
use Cbox\Id\AccessControl\Models\GroupRoleMapping;

/**
 * Refusing GroupRoleMappings binding for the 'external' RBAC driver. The directory
 * group→role bridge writes `pushed` role assignments into the built-in tables, which
 * are not loaded under an external driver, so every operation fails loud. Bind your
 * own adapter to reconcile SCIM/directory groups onto your backend's roles — see
 * docs/extension-points/custom-rbac.md.
 */
class UnboundGroupRoleMappings implements GroupRoleMappings
{
    public function map(string $organizationId, string $groupId, string $roleId, int $priority = 0): GroupRoleMapping
    {
        throw ExternalRbacNotBound::forContract(GroupRoleMappings::class);
    }

    public function unmap(string $organizationId, string $groupId, string $roleId): void
    {
        throw ExternalRbacNotBound::forContract(GroupRoleMappings::class);
    }

    public function forOrganization(string $organizationId): array
    {
        throw ExternalRbacNotBound::forContract(GroupRoleMappings::class);
    }

    public function reconcileUser(string $organizationId, string $userId): void
    {
        throw ExternalRbacNotBound::forContract(GroupRoleMappings::class);
    }

    public function reconcileGroup(string $groupId, ?string $organizationId = null): void
    {
        throw ExternalRbacNotBound::forContract(GroupRoleMappings::class);
    }
}
