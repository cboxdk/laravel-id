<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Closure;

/**
 * Resolves and holds the {@see Environment} for the current execution context —
 * the single source of truth the hard environment scope consults on every query.
 * Registered as a singleton for the lifetime of the request/job.
 *
 * There is deliberately NO roll-up ("scopedTo") on this dimension: environments
 * never aggregate into one another. The only relaxation is {@see withoutScope()},
 * a provisioning-only escape for the few genuinely environment-spanning kernel
 * operations (creating an environment, the control-plane admin surface).
 */
interface EnvironmentContext
{
    public function current(): ?Environment;

    /** @throws EnvironmentMissing */
    public function requireEnvironment(): Environment;

    public function has(): bool;

    public function set(?Environment $environment): void;

    /**
     * Run a callback with the given environment active, restoring the previous
     * one afterwards even if the callback throws.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    public function runAs(Environment $environment, Closure $callback): mixed;

    /**
     * Run a callback with the environment scope suspended. PROVISIONING-ONLY —
     * for creating environments and the control-plane admin surface, never for
     * ordinary request handling. Reference-counted for safe nesting.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    public function withoutScope(Closure $callback): mixed;

    public function isScopingSuspended(): bool;
}
