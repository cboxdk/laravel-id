<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Exceptions;

use RuntimeException;

/**
 * Thrown when an environment is required but none is set in the context — the
 * deny-by-default posture surfaced as an explicit failure rather than a leak.
 */
final class EnvironmentMissing extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('No environment is set in the current context.');
    }
}
