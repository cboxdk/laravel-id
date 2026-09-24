<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

use Cbox\Id\AccessControl\ValueObjects\PermissionDecision;

/**
 * Live RBAC answers for one app: "may this person do `invoices:approve` in this
 * organization, for this client?".
 *
 * The answer is the one a token minted right now would carry — the same
 * {@see AccessChecker::forToken()} the issuer stamps `permissions` from, so the org's
 * own grants, grants rolled down from ancestor organizations and environment-wide grants
 * all count, and another app's roles never do. What it adds over the token is freshness:
 * a revoked role or a suspended organization is visible on the next call, not at the
 * token's expiry.
 */
interface PermissionDecisions
{
    /**
     * @param  string|null  $organizationId  null asks only what is held environment-wide
     * @param  list<string>  $permissions  permission keys as the app declared them
     */
    public function decide(string $userId, ?string $organizationId, string $clientId, array $permissions): PermissionDecision;
}
