<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Models\Environment as EnvironmentModel;
use Illuminate\Support\Facades\DB;

/**
 * Resolves an environment from the request host: first an exact custom-domain
 * match, then the leading DNS label as a slug (e.g. `staging.auth.example.com`
 * → the `staging` environment) — but ONLY when the host sits under a configured
 * base domain, so a spoofed `staging.attacker.com` can never select a plane.
 * The Environment model is not itself environment-owned, so these lookups run
 * unscoped by design.
 *
 * A resolved environment only serves while it AND the customer who owns it are active:
 * a suspended environment, or one whose owner is suspended/delinquent, resolves
 * to null so the host stops serving auth entirely (the platform's off-switch for
 * an abusive or non-paying tenant actually cuts the end-user plane, not just the
 * dashboard).
 */
class DatabaseEnvironmentResolver implements EnvironmentResolver
{
    public function resolveForHost(string $host): ?Environment
    {
        $host = strtolower(trim($host));

        if ($host === '') {
            return null;
        }

        $byDomain = EnvironmentModel::query()->where('domain', $host)->first();

        if ($byDomain !== null) {
            return $this->servable($byDomain);
        }

        // Subdomain-slug resolution is only trusted under a configured base
        // domain. With none configured, exact custom-domain match is the only
        // path — never an attacker-chosen Host header.
        $label = explode('.', $host)[0];

        if ($label === '' || ! $this->hostIsUnderBaseDomain($host)) {
            return null;
        }

        return $this->servable(EnvironmentModel::query()->where('slug', $label)->first());
    }

    public function forKey(string $environmentKey): ?Environment
    {
        // Unscoped by id — a stored key (e.g. an outbox event's environment_id) may
        // be replayed with no ambient scope; liveness is NOT re-gated here because the
        // caller is rehydrating context for a past event, not serving a live request.
        return $environmentKey === '' ? null : EnvironmentModel::query()->find($environmentKey);
    }

    public function defaultEnvironment(): ?Environment
    {
        return $this->servable(EnvironmentModel::query()->where('is_default', true)->first());
    }

    /**
     * Gate a resolved environment on liveness: it must be active, and the customer who
     * owns it must be active too. Returns null when it must not serve.
     *
     * OWNERSHIP RUNS THROUGH THE PROJECT — environment → project → organization — which is
     * one hop longer than the `environments.account_id` this used to read, and worth it:
     * that column was a denormalized copy of the same fact, and a copy of ownership is a
     * second place for ownership to be wrong.
     *
     * An environment with no project is owned by nobody and serves: that is the platform
     * root, and a self-hosted single-tenant install's lone environment. Neither has a
     * customer to suspend, and refusing them would take the deployment down with a
     * question about a customer it does not have.
     *
     * Raw queries rather than the models on purpose. `organizations` is environment-owned,
     * so `Organization::query()` here would be scoped to whatever environment is CURRENT —
     * which, in a resolver whose whole job is to decide what the current environment is,
     * is either nothing or the wrong one.
     */
    private function servable(?EnvironmentModel $environment): ?EnvironmentModel
    {
        if ($environment === null || ! $environment->status->canServe()) {
            return null;
        }

        if ($environment->project_id === null) {
            return $environment;
        }

        $organizationId = DB::table('projects')->where('id', $environment->project_id)->value('organization_id');

        // A project that has gone missing, or one whose organization has, is not a licence
        // to serve. The environment names an owner; if that owner cannot be produced, the
        // safe reading is that it must not serve — the same direction a suspension takes.
        if (! is_string($organizationId) || $organizationId === '') {
            return null;
        }

        $ownerActive = DB::table('organizations')
            ->where('id', $organizationId)
            ->where('status', 'active')
            ->exists();

        return $ownerActive ? $environment : null;
    }

    private function hostIsUnderBaseDomain(string $host): bool
    {
        $bases = config('cbox-id.environments.base_domains', []);
        $bases = is_array($bases) ? $bases : [$bases];

        foreach ($bases as $base) {
            if (! is_string($base)) {
                continue;
            }

            $base = ltrim(strtolower($base), '.');

            if ($base !== '' && str_ends_with($host, '.'.$base)) {
                return true;
            }
        }

        return false;
    }
}
