<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

/**
 * A verified environment-admin handoff: the account member and the environment the
 * signed token binds together. Produced only by verifying a token the platform
 * itself minted, so it is proof that this account member was granted admin access
 * to this environment — the bridge that lets an account-layer identity administer a
 * tenant environment WITHOUT a second login and WITHOUT existing as a subject inside
 * that environment.
 */
final readonly class EnvironmentAdminGrant
{
    public function __construct(
        public string $accountMemberId,
        public string $environmentId,
    ) {}
}
