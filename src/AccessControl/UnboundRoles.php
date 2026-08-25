<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\ExternalRbacNotBound;
use Cbox\Id\AccessControl\Models\EnvironmentRoleAssignment;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;

/**
 * Refusing Roles binding for the 'external' RBAC driver. Role authoring and
 * assignment belong to the host's own backend when the built-in tables are not
 * loaded, so every operation fails loud rather than writing to a schema that does
 * not exist. Bind your own Roles adapter to use SCIM group→role sync or governance
 * under an external driver — see docs/extension-points/custom-rbac.md.
 */
class UnboundRoles implements Roles
{
    public function define(?string $organizationId, string $name, ?string $description = null, ?string $clientId = null): Role
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function grantPermission(?string $organizationId, string $roleId, string $permission): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function updateRole(string $roleId, string $name, ?string $description = null, ?string $organizationId = null): Role
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function attachPermission(string $roleId, string $permissionId, ?string $organizationId = null): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function revokePermission(string $roleId, string $permissionId, ?string $organizationId = null): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function deleteRole(string $roleId, ?string $organizationId = null): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function assertAssignableIn(string $organizationId, string $roleId): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function assign(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): RoleAssignment {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function unassign(string $organizationId, string $userId, string $roleId): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function unassignAll(string $organizationId, string $userId): int
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function assignmentsForSubject(string $organizationId, string $userId): array
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function assignEverywhere(string $userId, string $roleId, GrantSource $source = GrantSource::Manual): EnvironmentRoleAssignment
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function unassignEverywhere(string $userId, string $roleId): void
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function everywhereFor(string $userId): array
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }

    public function assignmentsInOrganization(string $organizationId): array
    {
        throw ExternalRbacNotBound::forContract(Roles::class);
    }
}
