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
     * Whether tenant scoping is currently suspended.
     */
    public function isScopingSuspended(): bool;
}
