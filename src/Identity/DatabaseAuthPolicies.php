<?php

declare(strict_types=1);

namespace Cbox\Id\Identity;

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Models\AuthPolicyRecord;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;

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
    // Lazy per-call resolution of the ambient environment. This class is a `singleton`
    // (IdentityServiceProvider) and EnvironmentContext is `scoped`, so injecting it here
    // would pin a queue worker to the first job's environment for the life of the process.
    use ResolvesEnvironment;

    /**
     * Per-request memo, keyed by ENVIRONMENT — resolve() is consulted on every credential
     * path, and this is a singleton.
     *
     * Keying matters because one process legitimately visits several environments: a
     * queue worker draining jobs for different tenants, and every `PlatformRoot::run()`
     * that steps into tenant 1 and back. An unkeyed memo would answer the first
     * environment's policy for all of them — applying one tenant's password floor to
     * another's people, in the direction the tighten-only rule exists to forbid.
     *
     * @var array<string, AuthPolicy>
     */
    private array $environmentPolicies = [];

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
        $key = $this->environments()->current()?->environmentKey() ?? '';

        return $this->environmentPolicies[$key] ??= AuthPolicyRecord::query()
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

        // Drop every key, not just this environment's: a write is rare, and a stale
        // entry for a scope this call was not made in is the failure being avoided.
        $this->environmentPolicies = [];
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
