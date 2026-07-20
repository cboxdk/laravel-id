<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;

interface Roles
{
    /**
     * Define (or fetch) a role. Org-wide when $clientId is null (its permissions
     * apply in every app's token); scoped to one app when $clientId is that app's
     * client id. Uniqueness is (organization_id, client_id, name).
     */
    public function define(?string $organizationId, string $name, ?string $description = null, ?string $clientId = null): Role;

    /**
     * Attach a permission to a role. The permission is resolved (and, if new,
     * created) within the ROLE's own scope — an app-scoped role's permissions live
     * under that app's client_id, an org-wide role's under client_id null — so a
     * permission name is never silently duplicated across scopes.
     */
    public function grantPermission(string $organizationId, string $roleId, string $permission): void;

    /**
     * Assert a role may be assigned within this organization — its own, or an
     * environment-wide system role. Throws UnknownRole otherwise.
     *
     * assign() applies this itself; it is exposed for callers that persist a role id
     * somewhere else first (e.g. a directory group→role mapping) and must refuse an
     * unusable one at the point of the write rather than at reconciliation.
     *
     * @throws UnknownRole
     */
    public function assertAssignableIn(string $organizationId, string $roleId): void;

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
