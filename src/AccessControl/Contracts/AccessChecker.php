<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\ValueObjects\AppAccessClaims;

/**
 * Coarse RBAC checks. Resolution is hierarchy-aware: roles assigned in an
 * ancestor org roll down to descendants (reseller/parent management).
 */
interface AccessChecker
{
    /**
     * Whether ANY role the user holds in the org — its own, an ancestor's, or one held
     * environment-wide — grants a permission of this name, WHATEVER APP DECLARED IT.
     *
     * Not an app's authorization question. Since 1.19 an environment-wide grant may name
     * one app's declared role (a staff role), and this answers across all of them: one
     * app's `support:impersonate` is a yes here for every other app too. A decision made
     * for one client must use {@see forToken()} with that client, or
     * {@see PermissionDecisions}, which does.
     */
    public function can(string $userId, string $permission, string $organizationId): bool;

    /**
     * The user's effective permission names in the org, across EVERY app's roles — see
     * {@see can()} for why this is not a per-app answer.
     *
     * @return list<string>
     */
    public function permissionsFor(string $userId, string $organizationId): array;

    /**
     * The user's effective roles + permissions AS THEY SHOULD BE STAMPED INTO A
     * TOKEN for one app: the org-wide roles they hold plus that app's own declared
     * roles (by client_id), and the union of those roles' permissions. Roles that
     * belong to OTHER apps are excluded, so an app's token never carries access it
     * doesn't own.
     *
     * `$organizationId` MAY BE NULL, and then the answer is what the user holds
     * environment-wide. A service provider with no tenancy of its own has no
     * organization to name, and a person who has joined none still has whatever they
     * were granted across the environment — before this, both got a token with no roles
     * and no permissions at all, and there was no way to give them any.
     */
    public function forToken(string $userId, ?string $organizationId, string $clientId): AppAccessClaims;
}
