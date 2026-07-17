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
 * A resolved environment only serves while it AND its owning account are active:
 * a suspended environment, or one whose account is suspended/delinquent, resolves
 * to null so the host stops serving auth entirely (the platform's off-switch for
 * an abusive or non-paying tenant actually cuts the end-user plane, not just the
 * dashboard).
 */
final class DatabaseEnvironmentResolver implements EnvironmentResolver
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

    public function defaultEnvironment(): ?Environment
    {
        return $this->servable(EnvironmentModel::query()->where('is_default', true)->first());
    }

    /**
     * Gate a resolved environment on liveness: it must be active, and its owning
     * account (if any) must be active. A null owning account is a platform-owned
     * environment (Cbox's own / self-hosted single tenant), which has no account to
     * suspend. Returns null when the environment must not serve.
     */
    private function servable(?EnvironmentModel $environment): ?EnvironmentModel
    {
        if ($environment === null || $environment->status !== 'active') {
            return null;
        }

        if ($environment->account_id !== null) {
            $accountActive = DB::table('accounts')
                ->where('id', $environment->account_id)
                ->where('status', 'active')
                ->exists();

            if (! $accountActive) {
                return null;
            }
        }

        return $environment;
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
