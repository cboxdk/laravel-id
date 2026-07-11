<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Testing;

use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Closure;

/**
 * Drop-in test ergonomics for anything that exercises tenant-scoped code.
 *
 * Ships with the package (not test-only) so downstream consumers get the same
 * `actingAs*` fluency they know from Laravel:
 *
 *     use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
 *
 *     uses(InteractsWithTenancy::class);
 *
 *     it('scopes to the acting tenant', function () {
 *         $this->actingAsTenant('org_123');
 *         // ... assertions against your tenant-owned models
 *     });
 *
 * The underlying {@see TenantContext} is an interface, so it can equally be
 * mocked or swapped in the container when you need full control.
 */
trait InteractsWithTenancy
{
    /**
     * Act as the given tenant for the remainder of the test.
     */
    protected function actingAsTenant(Tenant|string $tenant): Tenant
    {
        $tenant = is_string($tenant) ? GenericTenant::of($tenant) : $tenant;

        $this->tenantContext()->set($tenant);

        return $tenant;
    }

    /**
     * Run a callback as the given tenant, restoring the previous tenant after.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    protected function runAsTenant(Tenant|string $tenant, Closure $callback): mixed
    {
        $tenant = is_string($tenant) ? GenericTenant::of($tenant) : $tenant;

        return $this->tenantContext()->runAs($tenant, $callback);
    }

    /**
     * Run a callback with reads scoped to a set of tenant keys (roll-up).
     *
     * @template TReturn
     *
     * @param  list<string>  $keys
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    protected function actingAsTenants(array $keys, Closure $callback): mixed
    {
        return $this->tenantContext()->scopedTo($keys, $callback);
    }

    /**
     * Run a callback with tenant scoping suspended.
     *
     * @template TReturn
     *
     * @param  Closure():TReturn  $callback
     * @return TReturn
     */
    protected function withoutTenantScope(Closure $callback): mixed
    {
        return $this->tenantContext()->withoutScope($callback);
    }

    /**
     * Clear the current tenant.
     */
    protected function forgetTenant(): void
    {
        $this->tenantContext()->set(null);
    }

    private function tenantContext(): TenantContext
    {
        return app(TenantContext::class);
    }
}
