<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Exceptions;

use RuntimeException;

/**
 * A hook vetoed the operation (an action returned deny, or a fail-closed action
 * could not be run). The reason is the deciding action's reason string; the caller
 * maps it to whatever its protocol requires (the token endpoint → `access_denied`).
 */
class ActionDenied extends RuntimeException
{
    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
