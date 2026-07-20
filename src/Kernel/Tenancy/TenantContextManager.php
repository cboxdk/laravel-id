<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy;

use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\Exceptions\TenantMissing;
use Closure;

/**
 * In-memory implementation of {@see TenantContext}.
 *
 * Registered as a singleton, so the current tenant is stable for the duration
 * of a request or queued job. Suspension is reference-counted to support safe
 * nesting of {@see withoutScope()}.
 */
class TenantContextManager implements TenantContext
{
    private ?Tenant $current = null;

    private int $suspensions = 0;

    /**
     * Stack of active roll-up key sets, innermost last.
     *
     * @var list<list<string>>
     */
    private array $scopeSets = [];

    public function current(): ?Tenant
    {
        return $this->current;
    }

    public function requireTenant(): Tenant
    {
        return $this->current ?? throw new TenantMissing;
    }

    public function has(): bool
    {
        return $this->current !== null;
    }

    public function set(?Tenant $tenant): void
    {
        $this->current = $tenant;
    }

    public function runAs(Tenant $tenant, Closure $callback): mixed
    {
        $previous = $this->current;
        $this->current = $tenant;

        try {
            return $callback();
        } finally {
            $this->current = $previous;
        }
    }

    public function withoutScope(Closure $callback): mixed
    {
        $this->suspensions++;

        try {
            return $callback();
        } finally {
            $this->suspensions--;
        }
    }

    public function scopedTo(array $tenantKeys, Closure $callback): mixed
    {
        $this->scopeSets[] = $tenantKeys;

        try {
            return $callback();
        } finally {
            array_pop($this->scopeSets);
        }
    }

    public function activeScopeKeys(): ?array
    {
        if ($this->scopeSets === []) {
            return null;
        }

        return $this->scopeSets[array_key_last($this->scopeSets)];
    }

    public function isScopingSuspended(): bool
    {
        return $this->suspensions > 0;
    }
}
