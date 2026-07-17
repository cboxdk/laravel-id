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
    public function can(string $userId, string $permission, string $organizationId): bool;

    /**
     * @return list<string> the user's effective permission names in the org
     */
    public function permissionsFor(string $userId, string $organizationId): array;

    /**
     * The user's effective roles + permissions AS THEY SHOULD BE STAMPED INTO A
     * TOKEN for one app: the org-wide roles they hold plus that app's own declared
     * roles (by client_id), and the union of those roles' permissions. Roles that
     * belong to OTHER apps are excluded, so an app's token never carries access it
     * doesn't own.
     */
    public function forToken(string $userId, string $organizationId, string $clientId): AppAccessClaims;
}
