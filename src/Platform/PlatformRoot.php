<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Console\InstallCommand;
use Cbox\Id\Kernel\Runtime\RequestLifetime;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
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
    private ?Environment $memoModel = null;

    private ?RequestLifetime $memoLifetime = null;

    use ResolvesEnvironment;

    /**
     * NO CONSTRUCTOR-INJECTED {@see EnvironmentContext}, and this class is the reason the
     * rule exists rather than an exception to it.
     *
     * `EnvironmentContext` is a SCOPED binding — one instance per request. This object is
     * held by singletons (`AccountMembers` among them), so injecting the context here made
     * the singleton capture the FIRST request's instance and keep it forever. `run()` then
     * switched an environment nobody was reading: `model()` resolved the platform root
     * correctly, `runAs()` set it on a dead context, and the query inside ran under
     * whatever environment the live request had selected.
     *
     * It was invisible for as long as every caller read tables that are not
     * environment-owned — `accounts`, `account_members` — where running in the wrong
     * environment changes nothing. The first caller to read an environment-owned table
     * through it (`memberships`, when environment grants moved to the membership) found no
     * membership on a tenant host, so an account owner was refused the environment they
     * own and the console bounced: `/open → /admin/handoff → /admin/login → /open`.
     *
     * {@see ResolvesEnvironment} resolves the live context per call instead.
     */
    public function __construct() {}

    /**
     * The platform-root environment MODEL, or null when no `is_default` row exists.
     *
     * Callers that must write an environment-OWNED row (an organization, say) need the
     * real row — a configured key with no row behind it would produce an organization
     * pointing at an environment that does not exist.
     *
     * MEMOISED FOR THE REQUEST. Which environment is the root cannot change mid-request:
     * `is_default` is stamped once by the installer and moving it is a deployment event,
     * not a user action. An account-plane page paid this five times over — every
     * {@see run()} asks, and the account console asks on every member and account read.
     *
     * This does not weaken the laziness the class doc argues for. What must stay lazy is
     * the CONTEXT the callback runs in, because a request can legitimately move between
     * environments ({@see EnvironmentContext::runAs()}); the row this returns is a fact
     * about the deployment, and the same one from either side of such a move.
     * {@see RequestLifetime} bounds the memo to the request, so a `migrate` between two
     * requests on a long-lived worker is still seen.
     *
     * ONLY A FOUND ROW IS REMEMBERED. "There is no platform root" is the one answer that
     * DOES flip inside a request: {@see InstallCommand} and the first-run screen stamp the
     * root and then, in the same call, write the operator's subject into it — through this
     * class. A memoised null there would send that subject nowhere and leave the operator
     * on the local bootstrap hash, the single credential path that skips the password
     * policy. So the empty answer is re-asked, which costs a query only on a deployment
     * that has not been installed yet.
     */
    public function model(): ?Environment
    {
        $lifetime = RequestLifetime::current(app());

        if ($this->memoLifetime !== $lifetime) {
            $this->memoLifetime = $lifetime;
            $this->memoModel = null;
        }

        return $this->memoModel ??= Environment::query()->where('is_default', true)->first();
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

        return $environment === null ? null : $this->environments()->runAs($environment, $callback);
    }
}
