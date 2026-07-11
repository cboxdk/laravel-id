<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy;

use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;

/**
 * A minimal {@see Tenant} backed by a bare key.
 *
 * Use it when you already hold a tenant identifier (from a token, a job payload,
 * a webhook) and don't need the full Organization model — and as a zero-friction
 * convenience in tests. The Organization model is the production {@see Tenant}.
 */
final readonly class GenericTenant implements Tenant
{
    public function __construct(private string $key) {}

    public static function of(string $key): self
    {
        return new self($key);
    }

    public function tenantKey(): string
    {
        return $this->key;
    }
}
