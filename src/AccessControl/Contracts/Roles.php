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

    /*
     * --------------------------------------------------------------------------
     * Role lifecycle (control plane)
     * --------------------------------------------------------------------------
     * The three methods below manage the role CATALOG rather than a tenant's grants,
     * so they are keyed by role id alone and carry no organization argument: an
     * environment-wide role (organization_id null) is precisely the case an org-scoped
     * signature cannot express. Authorization is the caller's (an environment console
     * is already gated to its plane, and every model here is environment-scoped).
     *
     * They exist because these writes used to be raw `DB::table()` deletes in the
     * console: a change to privileged access affecting every holder of a role left NO
     * trace on the audit trail and emitted nothing, so no SIEM saw it and no
     * downstream app mirroring roles off `role.unassigned` ever learned.
     */

    /**
     * Rename a role / edit its description, recording the change.
     *
     * @throws UnknownRole
     */
    public function updateRole(string $roleId, string $name, ?string $description = null): Role;

    /**
     * Attach an ALREADY-DECLARED permission to a role by id, recording the change.
     * Unlike {@see grantPermission()} this never mints a permission, and the
     * permission need not share the role's scope — it is the console's "tick a key
     * from the catalog" operation. A no-op when already attached.
     *
     * @throws UnknownRole
     */
    public function attachPermission(string $roleId, string $permissionId): void;

    /**
     * Detach a permission from a role by id, recording the change. A no-op (and
     * silent) when the role never held it.
     *
     * @throws UnknownRole
     */
    public function revokePermission(string $roleId, string $permissionId): void;

    /**
     * Delete a role: its permission pivot rows, every live assignment of it, and the
     * role itself.
     *
     * Emits a `role.unassigned` per holder — the event downstream apps mirror grants
     * off — plus a single `role.deleted` naming the affected subjects, and audits
     * both. Roles are resolved live at token-mint time, so the privilege itself is
     * gone the moment the rows are, exactly as with {@see unassign()}; what this adds
     * is the record that it happened.
     *
     * @throws UnknownRole
     */
    public function deleteRole(string $roleId): void;

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
     * Drop every role this subject holds in the organization, and report how many went.
     *
     * Called when the subject stops being a member. Assignments are read by
     * (organization, user) with no membership join, so leaving them behind does not
     * merely litter: re-adding the person later silently restores privileges nobody
     * re-granted, and anything reading assignments directly still sees them as held.
     */
    public function unassignAll(string $organizationId, string $userId): int;

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
