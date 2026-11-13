<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Support;

use Cbox\Id\Organization\Enums\OrganizationStatus;
use Cbox\Id\Organization\Models\Organization;

/**
 * Whether an organization a credential speaks for is closed to it: its status
 * {@see OrganizationStatus::revokesAccess()} (suspended or archived).
 *
 * Read off the row above every scope. A token, a refresh grant, a SCIM directory and a
 * support session name their organization by id, and the question is that organization's
 * status wherever the request happens to stand; a scoped query from another context finds
 * no row and would answer "open". Ids are ULIDs, so the unscoped read answers for exactly
 * that organization.
 *
 * An id with no row is NOT closed. Every caller asks about an id a signed token or a stored
 * grant carries; failing all of them on a missing row would turn one erased organization
 * into an outage, and erasure takes the grants with it anyway.
 */
final class OrganizationStanding
{
    public static function isClosed(?string $organizationId): bool
    {
        if ($organizationId === null || $organizationId === '') {
            return false;
        }

        $status = Organization::query()->withoutGlobalScopes()->whereKey($organizationId)->value('status');

        if (is_string($status)) {
            $status = OrganizationStatus::tryFrom($status);
        }

        return $status instanceof OrganizationStatus && $status->revokesAccess();
    }
}
