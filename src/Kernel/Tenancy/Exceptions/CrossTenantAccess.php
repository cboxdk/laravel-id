<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Exceptions;

use RuntimeException;

/**
 * Thrown when an operation would cross the tenant isolation boundary — e.g.
 * persisting a row for a tenant other than the one currently in context.
 */
class CrossTenantAccess extends RuntimeException
{
    public static function forWrite(string $model, string $rowTenant, string $currentTenant): self
    {
        return new self(sprintf(
            'Refusing to write %s for tenant [%s] while acting as tenant [%s]. '
            .'Cross-tenant writes are forbidden; suspend scoping explicitly if this is a system operation.',
            $model,
            $rowTenant,
            $currentTenant,
        ));
    }
}
