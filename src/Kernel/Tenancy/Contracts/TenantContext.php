<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

use Cbox\Id\Kernel\Tenancy\Exceptions\TenantMissing;
use Closure;

/**
 * Resolves and holds the tenant for the current execution context.
 *
 * This is the single source of truth the global tenant scope consults on every
 * query. It is registered as a singleton for the lifetime of the request/job.
 */
interface TenantContext
{
    /**
     * The current tenant, or null when none is set.
     */
    public function current(): ?Tenant;

    /**
     * The current tenant, or throw when none is set.
     *
     * @throws TenantMissing
     */
    public function requireTenant(): Tenant;

    /**
     * Whether a tenant is currently set.
     */
    public function has(): bool;

    /**
     * Replace the current tenant (or clear it with null).
     */
    public function set(?Tenant $tenant): void;

    /**
     * Run a callback with the given tenant active, restoring the previous
     * tenant afterwards even if the callback throws.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    public function runAs(Tenant $tenant, Closure $callback): mixed;

    /**
     * Run a callback with tenant scoping suspended.
     *
     * KERNEL-ONLY escape hatch for legitimate cross-tenant operations
     * (system jobs, provisioning, reconciliation). Callers MUST write an audit
     * entry. Nested calls are reference-counted, so scoping only resumes once
     * the outermost suspension exits.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    public function withoutScope(Closure $callback): mixed;

    /**
     * Run a callback with reads constrained to an explicit SET of tenant keys.
     *
     * The bounded elevation used for authorized cross-tenant *reporting* — e.g.
     * a parent org rolling up its descendants. The set must be known, finite and
     * already authorized (typically the descendant keys from the org closure);
     * never unbounded. Deny-by-default still holds: an empty set matches zero
     * rows. Writes are NOT governed by this mode — mutate within a single tenant
     * via {@see runAs()}.
     *
     * @template TReturn
     *
     * @param  list<string>  $tenantKeys
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    public function scopedTo(array $tenantKeys, Closure $callback): mixed;

    /**
     * The active roll-up key set, or null when not inside a scopedTo() block.
     *
     * @return list<string>|null
     */
    public function activeScopeKeys(): ?array;

    /**
     * Whether tenant scoping is currently suspended.
     */
    public function isScopingSuspended(): bool;
}
