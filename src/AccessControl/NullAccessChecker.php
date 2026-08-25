<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\ValueObjects\AppAccessClaims;

/**
 * Deny-by-default AccessChecker for the 'external' RBAC driver. It is the binding a
 * host gets before it wires its own adapter: every check is refused and every token
 * is stamped with no roles or permissions, so a not-yet-configured platform can
 * never leak access. Bind your own AccessChecker to replace it — see
 * docs/extension-points/custom-rbac.md.
 */
class NullAccessChecker implements AccessChecker
{
    public function can(string $userId, string $permission, string $organizationId): bool
    {
        return false;
    }

    public function permissionsFor(string $userId, string $organizationId): array
    {
        return [];
    }

    public function forToken(string $userId, ?string $organizationId, string $clientId): AppAccessClaims
    {
        return new AppAccessClaims([], []);
    }
}
