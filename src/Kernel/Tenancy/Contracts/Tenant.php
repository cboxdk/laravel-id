<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Contracts;

/**
 * A tenant is the isolation boundary of the platform (an organization).
 *
 * The kernel deliberately depends on this narrow interface rather than the
 * concrete Organization model, so the tenancy layer stays free of any domain
 * dependency. The Organization model (Organization module) implements it.
 */
interface Tenant
{
    /**
     * The stable, unique identifier of this tenant.
     *
     * This is the exact value stored in tenant-owned rows' tenant column
     * (default `organization_id`) and compared against on every scoped query.
     */
    public function tenantKey(): string;
}
