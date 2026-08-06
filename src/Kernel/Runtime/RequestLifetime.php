<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Runtime;

use Cbox\Id\IdServiceProvider;
use Cbox\Id\Kernel\Authorization\CachedEntitlements;
use Cbox\Id\Kernel\Tenancy\EnvironmentContextManager;
use Cbox\Id\Platform\PlatformRoot;
use Illuminate\Contracts\Foundation\Application;

/**
 * A token whose IDENTITY is "this request, or this queued job" — for memos held by
 * objects that outlive one.
 *
 * The ordinary way to memoise something for a request is to bind the holder `scoped` and
 * keep the memo on the instance; {@see EnvironmentContextManager} is bound that way, and
 * so is most of the console. That idiom only works when NOTHING captures the holder, and
 * two of the hottest read paths in the platform are captured:
 *
 *  - {@see CachedEntitlements} is a `singleton`, and the host app decorates it inside
 *    another singleton, so re-binding it `scoped` would hand every later request the
 *    FIRST request's instance — the memo would go stale precisely where the class
 *    promises "instantly visible" (a cancelled plan still granting access, for the life
 *    of an Octane worker).
 *  - {@see PlatformRoot} is constructor-injected into several singletons, which each hold
 *    their own copy, so an instance memo there is per-HOLDER rather than per-request.
 *
 * Comparing a held token against the one the container resolves NOW answers "am I still
 * in the request I computed this in?" whoever holds the memo.
 * `Application::forgetScopedInstances()` runs between requests (Octane) and between
 * queued jobs, so the token is replaced exactly when a memo must be dropped, and never
 * during a request.
 *
 * Deliberately empty and deliberately final: it carries no state, because the only thing
 * anyone may ask of it is whether it is the same object as last time. Anything stored on
 * it would be request state hiding in a marker.
 *
 * Bound `scoped` by {@see IdServiceProvider}. Registered there rather than in a
 * module provider because an UNBOUND marker is worse than none: the container would build
 * a fresh instance per resolve, every comparison would miss, and the memos it guards would
 * quietly stop memoising with nothing to show for it.
 */
final class RequestLifetime
{
    /**
     * The token for the request in flight.
     *
     * Resolved through the container rather than injected, for the same reason the memos
     * that use it exist: the caller is an object that may outlive the request, so an
     * injected token would be exactly the stale value this is meant to detect.
     */
    public static function current(Application $app): self
    {
        return $app->make(self::class);
    }
}
