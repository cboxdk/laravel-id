<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentResolver;

/**
 * Caches host → environment resolution, which every single request pays for before
 * any endpoint logic runs.
 *
 * {@see DatabaseEnvironmentResolver::resolveForHost()} is 1 query on `domain`, then a
 * second on `slug` when that misses, and {@see DatabaseEnvironmentResolver} gates the
 * result on liveness with a third against `accounts`. `/.well-known/jwks.json`,
 * `/oauth/token`, `/oauth/userinfo` and `/oauth/decisions` therefore each paid 2–3
 * round trips up front, against a table that changes approximately never.
 *
 * `forKey()` is deliberately NOT cached. It is a single primary-key lookup used by the
 * outbox relay to rehydrate a stored `environment_id`, it runs off the request path,
 * and — unlike the host path — it intentionally does not gate liveness, so caching it
 * would add an invalidation surface with a different correctness rule for no
 * measurable gain.
 *
 * Set `cbox-id.environments.resolution_cache_ttl` to 0 to bypass entirely, which
 * restores the previous behaviour exactly.
 */
class CachedEnvironmentResolver implements EnvironmentResolver
{
    public function __construct(
        private readonly EnvironmentResolver $inner,
        private readonly EnvironmentResolutionCache $cache,
    ) {}

    public function resolveForHost(string $host): ?Environment
    {
        $host = strtolower(trim($host));

        if ($host === '' || ! $this->cache->enabled()) {
            return $this->inner->resolveForHost($host);
        }

        $cached = $this->cache->forHost($host);

        if ($cached !== null) {
            return $cached;
        }

        $resolved = $this->inner->resolveForHost($host);

        $this->cache->putHost($host, $resolved);

        return $resolved;
    }

    public function forKey(string $environmentKey): ?Environment
    {
        return $this->inner->forKey($environmentKey);
    }

    public function defaultEnvironment(): ?Environment
    {
        if (! $this->cache->enabled()) {
            return $this->inner->defaultEnvironment();
        }

        $cached = $this->cache->default();

        if ($cached !== null) {
            return $cached;
        }

        $resolved = $this->inner->defaultEnvironment();

        $this->cache->putDefault($resolved);

        return $resolved;
    }
}
