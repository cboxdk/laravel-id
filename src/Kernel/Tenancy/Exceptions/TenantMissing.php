<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Exceptions;

use RuntimeException;

/**
 * Thrown when a tenant is required but none is set in the current context.
 */
final class TenantMissing extends RuntimeException
{
    public function __construct(string $message = 'No tenant is set in the current context.')
    {
        parent::__construct($message);
    }
}
