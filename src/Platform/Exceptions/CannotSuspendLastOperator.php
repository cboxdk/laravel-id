<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use RuntimeException;

/**
 * Guards the invariant that the platform always keeps at least one active
 * operator: suspending the sole remaining active operator would lock every
 * human out of the control plane, so it is refused.
 */
final class CannotSuspendLastOperator extends RuntimeException
{
    public static function make(string $operatorId): self
    {
        return new self("Operator [{$operatorId}] is the last active operator and cannot be suspended.");
    }
}
