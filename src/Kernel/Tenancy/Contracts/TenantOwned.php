<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToTenant;

/**
 * Marks an Eloquent model as belonging to a tenant.
 *
 * Every tenant-owned model MUST implement this interface and use the
 * {@see BelongsToTenant} trait. The global
 * scope only engages for models implementing this contract, which keeps the
 * scope fully type-safe.
 */
interface TenantOwned
{
    /**
     * The column holding the tenant key on this model (default `organization_id`).
     */
    public function tenantColumn(): string;
}
