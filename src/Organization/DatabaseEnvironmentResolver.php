<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Models\Environment as EnvironmentModel;

/**
 * Resolves an environment from the request host: first an exact custom-domain
 * match, then the leading DNS label as a slug (e.g. `staging.auth.example.com`
 * → the `staging` environment) — but ONLY when the host sits under a configured
 * base domain, so a spoofed `staging.attacker.com` can never select a plane.
 * The Environment model is not itself environment-owned, so these lookups run
 * unscoped by design.
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
            return $byDomain;
        }

        // Subdomain-slug resolution is only trusted under a configured base
        // domain. With none configured, exact custom-domain match is the only
        // path — never an attacker-chosen Host header.
        $label = explode('.', $host)[0];

        if ($label === '' || ! $this->hostIsUnderBaseDomain($host)) {
            return null;
        }

        return EnvironmentModel::query()->where('slug', $label)->first();
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
