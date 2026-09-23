<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Contracts;

/**
 * What a person holds ENVIRONMENT-WIDE for one app — the question staff-only
 * capabilities (starting a support session) ask.
 *
 * Separate from {@see AccessChecker}, whose questions are all asked AT an organization.
 * A staff capability must not be satisfiable by a grant inside one customer: somebody who
 * holds "Support" in Acme alone is Acme's support, not the vendor's, and must not be able
 * to act as a member of every other customer. So this reads environment-wide grants only.
 */
interface StaffAccess
{
    /**
     * Whether an environment-wide grant gives this person the permission as DECLARED BY
     * this app: a non-orphaned role held everywhere, app-agnostic or the app's own, that
     * carries a non-orphaned permission of this name whose declaring client is `$clientId`.
     *
     * The permission must be the app's own declaration. A platform-wide permission that
     * happens to share the name is not the app saying "my staff may do this", and an app
     * that never declared it has not opted in to what it gates.
     */
    public function holdsEverywhere(string $userId, string $permission, string $clientId): bool;
}
