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

    /**
     * The same memo for per-ORGANIZATION overrides, keyed by environment AND organization
     * for the same reason.
     *
     * `forEnvironment()` above has been memoised from the start; `overrideFor()` four
     * lines down was not, and it is the one called in a LOOP. `PasswordExpiry` and
     * `MfaMandate` both walk the signed-in subject's memberships asking for each
     * organization's override, from the host's authentication middleware — which is also
     * persistent Livewire middleware, so it runs again on every round trip. Measured on
     * a console page: 17 queries at one organization, 22 at four, 32 at nine. Exactly
     * two per organization, on every request.
     *
     * A null override is memoised as null and must stay distinguishable from "not looked
     * up yet", hence array_key_exists rather than ??=.
     *
     * @var array<string, AuthPolicy|null>
     */
    private array $organizationPolicies = [];

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
        $key = $this->memoKey($organizationId);

        if (array_key_exists($key, $this->organizationPolicies)) {
            return $this->organizationPolicies[$key];
        }

        return $this->organizationPolicies[$key] = AuthPolicyRecord::query()
            ->where('organization_id', $organizationId)
            ->first()?->toPolicy();
    }

    public function overridesFor(array $organizationIds): array
    {
        $wanted = array_values(array_unique($organizationIds));
        $found = [];
        $missing = [];

        foreach ($wanted as $organizationId) {
            $key = $this->memoKey($organizationId);

            if (array_key_exists($key, $this->organizationPolicies)) {
                $policy = $this->organizationPolicies[$key];

                if ($policy !== null) {
                    $found[$organizationId] = $policy;
                }

                continue;
            }

            $missing[] = $organizationId;
        }

        if ($missing !== []) {
            $rows = AuthPolicyRecord::query()->whereIn('organization_id', $missing)->get();

            foreach ($rows as $row) {
                $organizationId = (string) $row->organization_id;
                $found[$organizationId] = $row->toPolicy();
                $this->organizationPolicies[$this->memoKey($organizationId)] = $found[$organizationId];
            }

            // Memoise the ABSENCES too, or a subject with no overrides re-reads every
            // organization on the next call — the exact cost this method exists to remove.
            foreach ($missing as $organizationId) {
                $this->organizationPolicies[$this->memoKey($organizationId)] ??= null;
            }
        }

        return $found;
    }

    private function memoKey(string $organizationId): string
    {
        return ($this->environments()->current()?->environmentKey() ?? '').'|'.$organizationId;
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

        // Whole memo, not one key. A write is rare; a policy read from a stale entry
        // under a scope this call was not made in is the failure worth avoiding.
        $this->organizationPolicies = [];
    }

    public function clearForOrganization(string $organizationId): void
    {
        AuthPolicyRecord::query()->where('organization_id', $organizationId)->delete();

        $this->organizationPolicies = [];
    }
}
