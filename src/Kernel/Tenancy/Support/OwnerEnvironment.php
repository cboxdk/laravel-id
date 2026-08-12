<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Support;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Cbox\Id\Organization\Models\Organization;

/**
 * Refuse to write a row owned by an organization that lives in another environment.
 *
 * `EnvironmentScope` stamps a new row with the AMBIENT environment and fences reads by it.
 * What it cannot see is the `organization_id` written alongside: nothing checks that the
 * named organization lives here. So a caller in environment E1 supplying an organization
 * from E2 gets a row stamped E1 that claims to belong to a tenant of E2 — an ownership
 * edge crossing a boundary the rest of the model treats as impermeable, and one that later
 * reads follow. A client registered that way mints `iss` of E1 carrying `org` of E2.
 *
 * `MembershipService::add()` has refused this since the boundary existed. This is that
 * check, lifted out so the other writers of an `organization_id` can share it rather than
 * each remembering.
 *
 * SUSPENSION IS AN ANSWER, NOT A BYPASS. Provisioning and backfill commands deliberately
 * declare that they run as the platform rather than inside a tenant, and there is no
 * ambient environment to cross INTO from there — refusing them would make the primitive
 * unusable from exactly the callers that legitimately create the first rows.
 */
class OwnerEnvironment
{
    /**
     * @param  class-string  $model  named in the refusal, so the message says what was refused
     *
     * @throws CrossEnvironmentAccess
     */
    public static function assertLocal(?string $organizationId, string $model): void
    {
        if ($organizationId === null || $organizationId === '') {
            return;
        }

        $environments = app(EnvironmentContext::class);

        if ($environments->isScopingSuspended()) {
            return;
        }

        $owner = Organization::query()
            ->withoutGlobalScope(EnvironmentScope::class)
            ->whereKey($organizationId)
            ->first();

        $current = $environments->current()?->environmentKey();

        if ($owner !== null && $owner->environment_id !== $current) {
            throw CrossEnvironmentAccess::forWrite($model, (string) $owner->environment_id, $current ?? 'none');
        }
    }
}
