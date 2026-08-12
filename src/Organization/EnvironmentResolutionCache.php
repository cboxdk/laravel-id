<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\Environment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Support\Facades\Cache;

/**
 * The cache behind {@see CachedEnvironmentResolver} — key scheme, reads, writes and
 * invalidation, in one place so the invalidating callers (the Environment model's own
 * events, and account suspension) never have to reproduce a key by hand.
 *
 * ## The key is the HOST, and nothing else
 *
 * Every key here is derived ONLY from arguments the caller passed in. It is never
 * built from a captured {@see EnvironmentContext} —
 * three singletons in this codebase (DatabaseEventBus, DatabaseAuditLog,
 * DatabaseKeyManager) each shipped exactly that bug, where a `scoped` context captured
 * by a `singleton` kept the first request's environment for the life of the process
 * and silently keyed every later request's cache entry to the wrong tenant.
 *
 * That failure mode cannot occur here, and not by luck: this cache runs BEFORE any
 * environment exists for the request — it is what decides which environment the
 * request is in. There is nothing to capture.
 *
 * ## Two levels, so suspension is immediate
 *
 * - `host:{host}` → the environment key that host resolves to.
 * - `env:{key}` → the resolved, LIVENESS-GATED environment.
 *
 * Suspending an environment (or its owning account) forgets the `env:` entry only.
 * The next request still finds the host mapping, misses the environment entry, and
 * falls through to a full live resolution — which now refuses. So the platform's
 * off-switch cuts traffic on the very next request, with no need to enumerate the
 * hosts an environment answers on, and reactivating restores it just as promptly
 * (see {@see forHost()} on why a refusal is never cached).
 *
 * Both kinds of host a row can answer on ARE enumerable from it, so both are
 * invalidated exactly: the custom `domain` (old and new), and the slug-derived
 * `{slug}.{base}` for every configured base domain — `base_domains` is precisely that
 * enumeration. {@see Models\Environment::booted()} forgets both
 * on save and on delete; a rename used to leave the old subdomain resolving for a full
 * TTL on the theory that a slug-derived host could not be enumerated, which it can. The
 * default TTL is 60 seconds, so anything this misses is still short-lived.
 */
class EnvironmentResolutionCache
{
    private const PREFIX = 'cbox-id:environment-resolution:';

    public const DEFAULT_TTL = 60;

    /**
     * How long "no environment serves this host" is remembered. Deliberately a fraction
     * of the positive TTL, and never longer than it — see {@see forHost()}.
     */
    public const ABSENT_TTL = 10;

    /** The marker stored for a host that resolves to nothing. Not a valid environment key. */
    private const ABSENT = '\0absent';

    /**
     * The environment a host resolves to, or null when the cache cannot answer and
     * the caller must resolve live.
     *
     * ## A negative is cached too, briefly
     *
     * This used to cache positives only, on the reasoning that a null has two very
     * different causes — the host maps to nothing, or it maps to something currently
     * refused — and remembering the second would mean reactivating an account did not
     * restore service until the entry lapsed.
     *
     * The reasoning was right and the conclusion was wrong, because it left the ONLY
     * uncacheable path also the cheapest to aim at. A host that maps to nothing pays
     * two or three database round trips, on every request, forever: point a wildcard
     * DNS record or a scanner at the platform and each request costs full lookups while
     * every real tenant's costs nothing. The load lands on the table the whole platform
     * resolves through.
     *
     * So a null is remembered for {@see ABSENT_TTL} seconds — a tenth of the positive
     * TTL — which bounds a flood to one resolution per host per ten seconds while
     * costing a reactivated account at most ten seconds of delay. The off-switch is
     * unaffected in the direction that matters: suspension still cuts traffic on the
     * very next request, because it forgets the `env:` entry and a host mapping without
     * one falls straight through to a live resolution that refuses.
     */
    public function forHost(string $host): ?Environment
    {
        $mapped = Cache::get($this->hostKey($host));

        if (! is_string($mapped) || $mapped === self::ABSENT) {
            return null;
        }

        $environment = Cache::get($this->environmentKey($mapped));

        return $environment instanceof Environment ? $environment : null;
    }

    /**
     * True when this host is known to resolve to nothing, so the caller can skip the
     * live lookup entirely.
     *
     * Separate from {@see forHost()} because that method's null already means "ask the
     * database" — a cached absence has to be a different answer or it is not a cache at
     * all.
     */
    public function knownAbsent(string $host): bool
    {
        return Cache::get($this->hostKey($host)) === self::ABSENT;
    }

    public function putHost(string $host, ?Environment $environment): void
    {
        $ttl = $this->ttl();

        if ($ttl <= 0) {
            return;
        }

        if ($environment === null) {
            Cache::put($this->hostKey($host), self::ABSENT, min(self::ABSENT_TTL, $ttl));

            return;
        }

        Cache::put($this->hostKey($host), $environment->environmentKey(), $ttl);
        Cache::put($this->environmentKey($environment->environmentKey()), $environment, $ttl);
    }

    /** Null when not cached — same positives-only rule as {@see forHost()}. */
    public function default(): ?Environment
    {
        $cached = Cache::get(self::PREFIX.'default');

        return $cached instanceof Environment ? $cached : null;
    }

    public function putDefault(?Environment $environment): void
    {
        $ttl = $this->ttl();

        if ($ttl <= 0 || $environment === null) {
            return;
        }

        Cache::put(self::PREFIX.'default', $environment, $ttl);
    }

    /**
     * Drop an environment's resolved entry. Enough on its own to make a suspension,
     * reactivation or settings change take effect on the next request.
     */
    public function forgetEnvironment(string $environmentKey): void
    {
        Cache::forget($this->environmentKey($environmentKey));
        Cache::forget(self::PREFIX.'default');
    }

    /** Drop a host mapping — used when a custom domain is attached or moved. */
    public function forgetHost(?string $host): void
    {
        if (is_string($host) && $host !== '') {
            Cache::forget($this->hostKey(strtolower(trim($host))));
        }
    }

    public function enabled(): bool
    {
        return $this->ttl() > 0;
    }

    /**
     * The configured subdomain base domains, normalised.
     *
     * Lives here rather than on the model because it is part of the key scheme: it is the
     * list a `{slug}.{base}` host key is built from, so the invalidating caller must not
     * have to reproduce the normalisation by hand.
     *
     * @return list<string>
     */
    public function baseDomains(): array
    {
        $configured = config('cbox-id.environments.base_domains', []);

        if (! is_array($configured)) {
            return [];
        }

        $bases = [];

        foreach ($configured as $base) {
            if (is_string($base) && trim($base) !== '') {
                $bases[] = strtolower(trim($base));
            }
        }

        return array_values(array_unique($bases));
    }

    private function ttl(): int
    {
        $ttl = config('cbox-id.environments.resolution_cache_ttl', self::DEFAULT_TTL);

        return is_numeric($ttl) ? (int) $ttl : self::DEFAULT_TTL;
    }

    private function hostKey(string $host): string
    {
        // Hashed so an arbitrarily long (attacker-supplied) Host header cannot produce an
        // oversized cache key — and hashed with SHA-256 rather than a fast
        // non-cryptographic digest, because the input IS attacker-controlled
        // (`$request->getHost()`) and this key decides which TENANT a request is served
        // as. xxh128 offers no collision resistance against someone searching for one, and
        // a found collision routes a request into another environment. Only positive
        // results are cached, so this was the one poisoning vector — and closing it costs
        // a few hundred nanoseconds on a path that is already doing a cache round trip.
        //
        // A cached ABSENT marker is written under the same key, and an attacker who found
        // a collision against one would only make a host resolve to nothing for ten
        // seconds — the same answer an unmapped host already gets.
        return self::PREFIX.'host:'.hash('sha256', $host);
    }

    private function environmentKey(string $environmentKey): string
    {
        return self::PREFIX.'env:'.$environmentKey;
    }
}
