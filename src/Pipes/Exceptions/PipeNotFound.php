<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * A management operation named a pipe that does not exist in the current environment.
 * A pipe in another environment is indistinguishable from one that does not exist.
 */
class PipeNotFound extends RuntimeException
{
    public static function forId(string $id): self
    {
        return new self("No pipe [{$id}] in this environment.");
    }

    public static function forProvider(string $provider): self
    {
        return new self("No enabled {$provider} pipe in this environment.");
    }
}
