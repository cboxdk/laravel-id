<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Console\InstallCommand;
use Cbox\Id\Kernel\Tenancy\Contracts\Environment as EnvironmentContract;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Organization\Models\Environment;
use Closure;

/**
 * Locates the PLATFORM-ROOT environment — "tenant 1", the environment the platform's
 * own control-plane people live in.
 *
 * Account members are ordinary subjects there rather than a second credential store, so
 * anything that reads or writes an account member's identity has to run inside that
 * environment's scope: subjects, memberships and sessions are all environment-owned, and
 * the tenancy kernel is deny-by-default, so a query run under a TENANT's scope would
 * silently see nothing (or worse, write into the tenant). This class is the one place
 * that answers "which environment is that", so the answer cannot drift between callers.
 *
 * Resolution order, deliberately:
 *
 *  1. The database `is_default` environment. This is the authoritative marker — it is
 *     what {@see InstallCommand} stamps, and it survives a
 *     horizontally-scaled deployment because it is not per-process configuration.
 *  2. Otherwise the configured default (`cbox-id.environments.default`), for deployments
 *     that pin their root by config and never stamped a row — but ONLY when that key
 *     resolves to a real environment that no account owns. The platform root is where
 *     the platform's own people are written; a config key aimed at a customer's
 *     environment would put every account member inside that customer's tenant.
 *
 * Both may be absent on a brand-new install, in which case there is NO platform root and
 * the callers degrade explicitly rather than inventing one.
 */
class PlatformRoot
{
    public function __construct(
        private readonly EnvironmentContext $environments,
    ) {}

    /**
     * The platform-root environment MODEL, or null when no `is_default` row exists.
     *
     * Callers that must write an environment-OWNED row (an organization, say) need the
     * real row — a configured key with no row behind it would produce an organization
     * pointing at an environment that does not exist.
     */
    public function model(): ?Environment
    {
        return Environment::query()->where('is_default', true)->first();
    }

    /**
     * The platform-root environment for SCOPING purposes, or null when the deployment
     * has neither an `is_default` row nor a configured default.
     */
    public function environment(): ?EnvironmentContract
    {
        $model = $this->model();

        if ($model !== null) {
            return $model;
        }

        $configured = config('cbox-id.environments.default');

        if (! is_string($configured) || $configured === '') {
            return null;
        }

        // The configured key is resolved to a REAL ROW and refused if that row belongs to
        // an account. This is where the platform's own people get written: a deployment
        // that never stamped `is_default` and pointed the config at a customer's
        // environment would put every account member inside that customer's tenant, where
        // its environment admins could set their password and sign in as them.
        //
        // Requiring a row also matches what the callers actually need — model() already
        // does, since an organization cannot point at an environment that does not exist.
        $row = Environment::query()->where('id', $configured)->orWhere('slug', $configured)->first();

        return $row !== null && $row->account_id === null ? $row : null;
    }

    /**
     * Run a callback inside the platform root's scope, or return null when there is no
     * platform root to run in.
     *
     * Returning null (rather than running the callback unscoped) is the safe failure: an
     * unscoped identity write would land in whatever environment happened to be current
     * — a tenant's, on a tenant host — which is precisely the leak the environment scope
     * exists to prevent.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn|null
     */
    public function run(Closure $callback): mixed
    {
        $environment = $this->environment();

        return $environment === null ? null : $this->environments->runAs($environment, $callback);
    }
}
