<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\PermissionDecisions;
use Cbox\Id\AccessControl\ValueObjects\PermissionCheck;
use Cbox\Id\AccessControl\ValueObjects\PermissionDecision;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;

/**
 * {@see PermissionDecisions} over the token's own resolver. Deliberately NOT
 * {@see AccessChecker::can()}: that answers across every app's roles, and a decision
 * made for one client must see exactly what that client's token would carry.
 */
class AppPermissionDecisions implements PermissionDecisions
{
    public function __construct(
        private readonly AccessChecker $access,
        private readonly Memberships $memberships,
        private readonly Organizations $organizations,
    ) {}

    public function decide(string $userId, ?string $organizationId, string $clientId, array $permissions): PermissionDecision
    {
        $active = true;
        $role = null;

        if ($organizationId !== null) {
            $active = ! ($this->organizations->find($organizationId)?->status->revokesAccess() ?? false);
            $role = $this->memberships->activeRole($organizationId, $userId);
        }

        $held = $active ? $this->access->forToken($userId, $organizationId, $clientId)->permissions : [];

        $checks = [];

        foreach ($permissions as $permission) {
            $checks[] = new PermissionCheck($permission, in_array($permission, $held, true));
        }

        return new PermissionDecision($userId, $organizationId, $clientId, $role, $active, $checks);
    }
}
