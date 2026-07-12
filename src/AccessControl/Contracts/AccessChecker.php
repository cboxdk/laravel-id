<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

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
}
