<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\EnvironmentRoleAssignment;
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
     *
     * `$organizationId` null names the ENVIRONMENT plane, as it does everywhere else in
     * this contract: an environment-wide role belongs to no tenant, and asking a tenant
     * to own the grant would be asking them to edit a role they do not own.
     */
    public function grantPermission(?string $organizationId, string $roleId, string $permission): void;

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
    public function updateRole(string $roleId, string $name, ?string $description = null, ?string $organizationId = null): Role;

    /**
     * Attach an ALREADY-DECLARED permission to a role by id, recording the change.
     * Unlike {@see grantPermission()} this never mints a permission, and the
     * permission need not share the role's scope — it is the console's "tick a key
     * from the catalog" operation. A no-op when already attached.
     *
     * @throws UnknownRole
     */
    public function attachPermission(string $roleId, string $permissionId, ?string $organizationId = null): void;

    /**
     * Detach a permission from a role by id, recording the change. A no-op (and
     * silent) when the role never held it.
     *
     * @throws UnknownRole
     */
    public function revokePermission(string $roleId, string $permissionId, ?string $organizationId = null): void;

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
    public function deleteRole(string $roleId, ?string $organizationId = null): void;

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
     * The role ids a subject effectively holds AT this organization: its DIRECT
     * assignments (not the hierarchy-rolled-up set — an inherited grant lives on, and is
     * read from, the ancestor org where it was assigned) PLUS any held environment-wide.
     * Read surface for governance (certification / SoD).
     *
     * IDS, NOT MODELS. Both callers mapped straight to `role_id`, and an environment-wide
     * grant is a different row in a different table — returning models would have forced
     * the two kinds into one type, or left the environment-wide ones out of the one
     * question segregation of duties asks. A toxic pair spanning the two kinds is exactly
     * the combination nobody thinks to look for.
     *
     * @return list<string>
     */
    public function assignmentsForSubject(string $organizationId, string $userId): array;

    /**
     * Grant a role EVERYWHERE in this environment rather than inside one organization —
     * for a support agent who acts across every customer, somebody who has joined no
     * organization, or a service provider with no tenancy of its own.
     *
     * Only an environment-wide role (no organization, no declaring app) may be granted
     * this way: one tenant's role handed out across the environment would give every
     * other tenant a policy they did not define.
     */
    public function assignEverywhere(string $userId, string $roleId, GrantSource $source = GrantSource::Manual): EnvironmentRoleAssignment;

    /** Take back an environment-wide grant. */
    public function unassignEverywhere(string $userId, string $roleId): void;

    /**
     * The role ids this user holds everywhere in the environment.
     *
     * @return list<string>
     */
    public function everywhereFor(string $userId): array;

    /**
     * Every DIRECT role assignment made AT this organization, across all subjects —
     * the grants an access-review campaign scoped to this org enumerates.
     *
     * @return list<RoleAssignment>
     */
    public function assignmentsInOrganization(string $organizationId): array;
}
