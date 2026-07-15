<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;

interface Roles
{
    public function define(?string $organizationId, string $name, ?string $description = null): Role;

    public function grantPermission(string $organizationId, string $roleId, string $permission): void;

    public function assign(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): RoleAssignment;

    public function unassign(string $organizationId, string $userId, string $roleId): void;

    /**
     * The DIRECT role assignments a subject holds AT this organization (not the
     * hierarchy-rolled-up effective set — an inherited grant lives on, and is read
     * from, the ancestor org where it was assigned). Read surface for governance
     * (certification / SoD).
     *
     * @return list<RoleAssignment>
     */
    public function assignmentsForSubject(string $organizationId, string $userId): array;

    /**
     * Every DIRECT role assignment made AT this organization, across all subjects —
     * the grants an access-review campaign scoped to this org enumerates.
     *
     * @return list<RoleAssignment>
     */
    public function assignmentsInOrganization(string $organizationId): array;
}
