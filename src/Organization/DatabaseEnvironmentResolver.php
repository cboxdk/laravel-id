<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;
use Cbox\Id\Organization\Models\Environment as EnvironmentModel;

/**
 * Resolves an environment from the request host: first an exact custom-domain
 * match, then the leading DNS label as a slug (e.g. `staging.auth.example.com`
 * → the `staging` environment). The Environment model is not itself
 * environment-owned, so these lookups run unscoped by design.
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

        $label = explode('.', $host)[0];

        return $label !== '' ? EnvironmentModel::query()->where('slug', $label)->first() : null;
    }
}
