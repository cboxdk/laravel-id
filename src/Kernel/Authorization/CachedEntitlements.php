<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * A hot-path cache over the entitlement projection. Reads are served from cache
 * so an authorization check on every request is sub-millisecond; every write
 * bumps a per-org version, which makes the change **instantly** visible on the
 * next read (a billing downgrade, cancellation or kill-switch takes effect now,
 * not after a token expires). No token is involved: the access token stays a thin
 * identity/scope bearer, and entitlements are resolved live.
 *
 * Invalidation is version-tagged rather than key-deleting: the read key embeds the
 * org's current version, so a write (which increments the version) simply routes
 * the next read to a fresh key — atomic, and correct even across cache nodes.
 */
class CachedEntitlements implements EntitlementReader, EntitlementWriter
{
    /** A backstop TTL; correctness comes from the version bump, not expiry. */
    private const TTL_SECONDS = 300;

    public function __construct(
        private readonly DatabaseEntitlements $inner,
        private readonly Cache $cache,
    ) {}

    public function get(string $organizationId, string $key): ?EntitlementValue
    {
        return $this->all($organizationId)[$key] ?? null;
    }

    public function all(string $organizationId): array
    {
        $version = $this->version($organizationId);

        /** @var array<string, EntitlementValue> $map */
        $map = $this->cache->remember(
            "cbox-ent:{$organizationId}:{$version}",
            self::TTL_SECONDS,
            fn (): array => $this->inner->all($organizationId),
        );

        return $map;
    }

    public function set(string $organizationId, EntitlementInput $input, EntitlementSource $source, ?string $sourceRef = null): EntitlementValue
    {
        $value = $this->inner->set($organizationId, $input, $source, $sourceRef);
        $this->invalidate($organizationId);

        return $value;
    }

    public function revoke(string $organizationId, string $key, EntitlementSource $source): void
    {
        $this->inner->revoke($organizationId, $key, $source);
        $this->invalidate($organizationId);
    }

    public function reconcile(string $organizationId, array $authoritative, EntitlementSource $source): void
    {
        $this->inner->reconcile($organizationId, $authoritative, $source);
        $this->invalidate($organizationId);
    }

    private function version(string $organizationId): int
    {
        $version = $this->cache->get("cbox-ent-ver:{$organizationId}");

        return is_numeric($version) ? (int) $version : 0;
    }

    /**
     * Bump the org's entitlement version so the next read misses the (now stale)
     * cache and reloads from the source of truth — instant propagation.
     */
    private function invalidate(string $organizationId): void
    {
        $key = "cbox-ent-ver:{$organizationId}";

        // increment() is atomic where the store supports it; seed it otherwise.
        if ($this->cache->increment($key) === false) {
            $this->cache->forever($key, $this->version($organizationId) + 1);
        }
    }
}
