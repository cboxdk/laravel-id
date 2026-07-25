<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Models\AuthPolicyRecord;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;

/**
 * The default {@see AuthPolicies}: policies live in the `auth_policies` table, scoped by
 * the environment global scope, with a null `organization_id` marking the baseline.
 *
 * Resolution is always environment-baseline THEN organization-override tightened on top
 * ({@see AuthPolicy::tightenedWith()}), so no caller can accidentally apply an override
 * that weakens the operator's floor.
 */
class DatabaseAuthPolicies implements AuthPolicies
{
    /** Per-request memo — resolve() is consulted on every credential path. */
    private ?AuthPolicy $environmentPolicy = null;

    public function resolve(?string $organizationId = null): AuthPolicy
    {
        $base = $this->forEnvironment();

        if ($organizationId === null) {
            return $base;
        }

        $override = $this->overrideFor($organizationId);

        return $override === null ? $base : $base->tightenedWith($override);
    }

    public function forEnvironment(): AuthPolicy
    {
        return $this->environmentPolicy ??= AuthPolicyRecord::query()
            ->whereNull('organization_id')
            ->first()?->toPolicy() ?? new AuthPolicy;
    }

    public function overrideFor(string $organizationId): ?AuthPolicy
    {
        return AuthPolicyRecord::query()
            ->where('organization_id', $organizationId)
            ->first()?->toPolicy();
    }

    public function setForEnvironment(AuthPolicy $policy): void
    {
        AuthPolicyRecord::query()->updateOrCreate(
            ['organization_id' => null],
            AuthPolicyRecord::columnsFor($policy),
        );

        $this->environmentPolicy = null;
    }

    public function setForOrganization(string $organizationId, AuthPolicy $policy): void
    {
        AuthPolicyRecord::query()->updateOrCreate(
            ['organization_id' => $organizationId],
            AuthPolicyRecord::columnsFor($policy),
        );
    }

    public function clearForOrganization(string $organizationId): void
    {
        AuthPolicyRecord::query()->where('organization_id', $organizationId)->delete();
    }
}
