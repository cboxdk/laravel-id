<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl;

use Cbox\Id\AccessControl\Contracts\GrantGuard;
use Cbox\Id\AccessControl\Enums\GrantSource;

/**
 * The default {@see GrantGuard}: nothing is refused.
 *
 * Named for what it does, in the same spirit as the package's other honest defaults — a
 * host reading its container bindings can see at a glance that no conflict policy is
 * being enforced, rather than assuming one is. `GovernanceServiceProvider` replaces it
 * with the segregation-of-duties implementation, so a deployment that loads governance
 * gets the real gate without wiring anything.
 */
class AllowAllGrants implements GrantGuard
{
    public function refuse(
        string $organizationId,
        string $userId,
        string $roleId,
        GrantSource $source = GrantSource::Manual,
    ): ?string {
        return null;
    }
}
