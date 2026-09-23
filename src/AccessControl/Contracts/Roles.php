<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Exceptions\GrantRefused;
use Cbox\Id\AccessControl\Exceptions\RoleNotTenantAssignable;
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
     *
     * `$tenantAssignable` false defines a STAFF role: never offered to, nor accepted
     * from, the organization plane (see {@see assertTenantAssignable()}). It applies
     * when the role is created; an existing role is fetched unchanged — use
     * {@see updateRole()} to change the flag on one.
     */
    public function define(?string $organizationId, string $name, ?string $description = null, ?string $clientId = null, bool $tenantAssignable = true): Role;

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
     * `$tenantAssignable` null leaves the staff flag as it is; a boolean sets it. The
     * organization fence applies to it like every other field: a tenant (`$organizationId`
     * set) resolves only its own roles, so it can never un-mark an environment's staff
     * role.
     *
     * @throws UnknownRole
     */
    public function updateRole(string $roleId, string $name, ?string $description = null, ?string $organizationId = null, ?bool $tenantAssignable = null): Role;

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

    /**
     * The ENVIRONMENT plane's grant: any role this organization may hold, including a
     * staff-only one. An environment administrator granting their support lead the
     * vendor's "Support" role inside one customer — tenant-specific staff rights — is
     * this call. A tenant-facing surface must use {@see assignAsTenant()} instead.
     */
    public function assign(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): RoleAssignment;

    /*
     * --------------------------------------------------------------------------
     * The organization (tenant) plane
     * --------------------------------------------------------------------------
     * What a TENANT administrator may see and grant. The difference from assign() is
     * staff roles (`tenant_assignable` false): the app vendor's own support and admin
     * roles, which usually carry rights across every customer. A customer handing one
     * to their own member would be a privilege escalation out of their tenancy, so the
     * tenant plane neither lists them nor accepts their id.
     */

    /**
     * The roles a tenant administrator of this organization may offer: its own roles
     * plus the environment's shared ones, minus staff-only and orphaned roles. With
     * `$clientId`, narrowed to that app's declared roles plus the app-agnostic ones.
     * Sorted by name.
     *
     * @return list<Role>
     */
    public function tenantAssignableRoles(string $organizationId, ?string $clientId = null): array;

    /**
     * Refuse a role a tenant may not grant in this organization — the guard behind
     * {@see tenantAssignableRoles()}, sharing its predicate so the list and the write
     * cannot disagree.
     *
     * @throws RoleNotTenantAssignable (an {@see UnknownRole}, so existing "not found"
     *                                 mappings keep holding)
     */
    public function assertTenantAssignable(string $organizationId, string $roleId): void;

    /**
     * {@see assign()}, from the organization plane: refuses a staff-only role before
     * anything is written. Every tenant-facing grant path — a tenant console, an
     * invitation carrying roles, a tenant-configured directory mapping — belongs here.
     *
     * @throws RoleNotTenantAssignable
     * @throws GrantRefused
     */
    public function assignAsTenant(
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
     * Any role with no owning organization may be granted this way, whether it is
     * app-agnostic (`client_id` null — it then appears in every app's token) or declared
     * by one app (it then appears in THAT app's tokens only, never another's). One
     * tenant's role handed out across the environment would give every other tenant a
     * policy they did not define, so an organization's role is refused, as is an
     * orphaned one.
     *
     * @throws UnknownRole
     * @throws GrantRefused when segregation of duties refuses it in any organization the
     *                      person belongs to
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
