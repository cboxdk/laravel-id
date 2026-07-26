<?php

declare(strict_types=1);

namespace Cbox\Id\Support;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;

/**
 * Merges this package's `config/cbox-id.php` defaults UNDER a host application's
 * own `config/cbox-id.php`, key by key, all the way down.
 *
 * WHY THIS EXISTS INSTEAD OF `ServiceProvider::mergeConfigFrom()`
 * ---------------------------------------------------------------
 * The framework helper is a single `array_merge()`, which only merges the TOP
 * level. A host that publishes a partial `config/cbox-id.php` — the normal way to
 * override one setting — therefore REPLACES the package's whole block for every
 * top-level key it names. In cbox-id, a `config/cbox-id.php` that declared nothing
 * but `oauth.authorization_endpoint_path` and two `webauthn` keys deleted eight
 * package defaults outright, so `CBOX_ID_ACCESS_TOKEN_TTL`, `CBOX_ID_DCR_MODE`,
 * `CBOX_ID_REQUIRE_PAR`, `CBOX_ID_DECISIONS_MAX_BATCH`, `CBOX_ID_CIBA_*` and
 * `CBOX_ID_WEBAUTHN_USER_VERIFICATION` were inert: an operator could set them and
 * nothing anywhere would read them. Every consumer passes an in-code fallback to
 * `config()`, so the product kept working on the hard-coded default and said
 * nothing. Silence is the whole problem — a knob that is documented, published and
 * unreachable is worse than one that was never offered.
 *
 * THE RULES (deliberately narrower than a generic "array merge recursive")
 * -----------------------------------------------------------------------
 * 1. The HOST always wins on any key it defines. A default is only ever filled in
 *    where the host is SILENT. Nothing the host wrote is rewritten or appended to.
 * 2. Recursion happens only where BOTH sides are associative arrays — i.e. where
 *    the array is a namespace of settings, and "fill in the ones you did not
 *    mention" is what the host meant.
 * 3. A LIST (sequential array: `allowed_scopes`, `api.middleware`, …) is a VALUE,
 *    not a namespace. A host list REPLACES the package list wholesale; it is never
 *    concatenated. Concatenating is the trap that makes shrinking a default list
 *    impossible — a host narrowing `allowed_scopes` to `['openid']` would silently
 *    get `profile`, `email` and `offline_access` grafted back on, and would have no
 *    way at all to express an empty list. Removing a default that is a list is
 *    therefore still fully expressible after this change.
 * 4. A type change wins for the host too: if the package ships an array and the
 *    host writes a scalar (or the reverse), the host's value stands unmerged.
 *
 * The one behaviour a host LOSES is removing a single scalar default by omitting a
 * sibling key — that was never an override, only an accident of `array_merge`, and
 * a host that genuinely wants a package default gone sets it to `null`/`false`
 * explicitly, which rule 1 honours.
 */
final class PackageConfigMerger
{
    /**
     * Load `$path` and merge it underneath whatever the host already has at
     * `$key`, then write the result back to the config repository.
     *
     * A no-op when the host's config is cached, matching the framework helper:
     * the cache file already contains the merged result from when it was built.
     */
    public static function mergeInto(Application $app, string $path, string $key): void
    {
        if ($app instanceof CachesConfiguration && $app->configurationIsCached()) {
            return;
        }

        $repository = $app->make(Repository::class);

        $defaults = require $path;

        if (! is_array($defaults)) {
            return;
        }

        $host = $repository->get($key, []);

        /** @var array<array-key, mixed> $defaults */
        $repository->set($key, self::merge($defaults, is_array($host) ? $host : []));
    }

    /**
     * Fill every key the host did not define with the package default, recursing
     * into associative arrays only. Public so the rules above are directly
     * testable without booting a container.
     *
     * @param  array<array-key, mixed>  $defaults
     * @param  array<array-key, mixed>  $host
     * @return array<array-key, mixed>
     */
    public static function merge(array $defaults, array $host): array
    {
        foreach ($defaults as $key => $default) {
            if (! array_key_exists($key, $host)) {
                $host[$key] = $default;

                continue;
            }

            $configured = $host[$key];

            // Rule 2 + rule 3: recurse into a shared namespace of settings; leave
            // anything the host expressed as a list (or as a scalar) untouched.
            if (is_array($default) && is_array($configured) && ! array_is_list($default) && ! array_is_list($configured)) {
                $host[$key] = self::merge($default, $configured);
            }
        }

        return $host;
    }
}
