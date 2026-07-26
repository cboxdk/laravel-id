<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Contracts\EntitlementWriter;
use Cbox\Id\Kernel\Authorization\Enums\EntitlementSource;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementInput;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Kernel\Crypto\DatabaseKeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
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
 *
 * Every key is ENVIRONMENT-SCOPED (same shape as {@see DatabaseKeyManager}).
 * {@see Models\Entitlement} is environment-owned, but the cache prefix is app-global and
 * environments share one store, so an org id — a ULID, identical on every host — produced
 * the literally same key in two environments. The DB read was correctly scoped; the cache
 * HIT was not, so environment A's warm answer was served as environment B's, handing B a
 * live entitlement it was never granted. Deterministic rather than a race: an attacker
 * warms A's key on demand and reuses it on B for the value TTL.
 */
class CachedEntitlements implements EntitlementReader, EntitlementWriter
{
    /** A backstop TTL; correctness comes from the version bump, not expiry. */
    private const TTL_SECONDS = 300;

    /**
     * The version counter must outlive the values it tags — a version that expires
     * before its value key would re-address a stale snapshot. Long, but not `forever`:
     * a dead org's counter should not sit in the store for the lifetime of the process.
     */
    private const VERSION_TTL_SECONDS = 2_592_000;

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
            'cbox-ent:'.$this->envId().':'.$organizationId.':'.$version,
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
        $key = $this->versionKey($organizationId);
        $version = $this->cache->get($key);

        if (is_numeric($version)) {
            return (int) $version;
        }

        // The counter is GONE — evicted under `allkeys-lru`, or never written. Seeding it
        // back at 0 would RESURRECT a pre-invalidation snapshot: a value key from before
        // the last bump can still be live under its 300s TTL, and version 0 addresses it
        // again — silently restoring a cancelled plan, the exact opposite of this class's
        // "instantly visible" promise.
        //
        // Seed RANDOMLY rather than trying to pick a "higher" version. A wall-clock seed
        // is only monotonic against a single clock: two nodes with skewed clocks (or one
        // NTP step backwards) re-seed BELOW a version this org has already held, and a
        // value key still live at that version resurrects exactly the revoked entitlement
        // this is meant to prevent. A random 63-bit seed needs no clock assumption at all;
        // colliding with one of the handful of value keys live for this org inside a
        // 300-second TTL is negligible, and the address space is the same one the counter
        // walks anyway.
        $seed = random_int(1, PHP_INT_MAX);

        // add() is a no-op if another process seeded first; re-read so both agree.
        $this->cache->add($key, $seed, self::VERSION_TTL_SECONDS);
        $stored = $this->cache->get($key);

        return is_numeric($stored) ? (int) $stored : $seed;
    }

    /**
     * Bump the org's entitlement version so the next read misses the (now stale)
     * cache and reloads from the source of truth — instant propagation.
     */
    private function invalidate(string $organizationId): void
    {
        $key = $this->versionKey($organizationId);

        // Read first so the counter is guaranteed to EXIST (seeded from the clock when
        // absent) before it is bumped: a bare increment on a missing key creates it at 1
        // on some stores, and version 1 may still address a live, stale value key.
        $current = $this->version($organizationId);

        // increment() is atomic where the store supports it, and preserves the key's
        // TTL; seed it explicitly otherwise.
        if ($this->cache->increment($key) === false) {
            $this->cache->put($key, $current + 1, self::VERSION_TTL_SECONDS);
        }
    }

    private function versionKey(string $organizationId): string
    {
        return 'cbox-ent-ver:'.$this->envId().':'.$organizationId;
    }

    /**
     * The current environment's key, resolved LAZILY per call — never captured on the
     * instance. This class is a singleton while EnvironmentContext is `scoped`, so a
     * constructor-injected context would go stale after the first job in a long-lived
     * worker (Octane/queue) and key the cache to the wrong environment. Same reasoning
     * as {@see EnvironmentScope}.
     */
    private function envId(): string
    {
        return app(EnvironmentContext::class)->current()?->environmentKey() ?? 'global';
    }
}
