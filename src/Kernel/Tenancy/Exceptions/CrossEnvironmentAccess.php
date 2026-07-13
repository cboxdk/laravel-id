<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Tenancy\Exceptions;

use RuntimeException;

/**
 * Thrown when a write would persist a row into an environment other than the one
 * currently active — the environment boundary is absolute and never crossed by a
 * mutation (there is no roll-up or elevation across environments).
 */
final class CrossEnvironmentAccess extends RuntimeException
{
    public static function forWrite(string $model, string $actual, string $expected): self
    {
        return new self("Refusing cross-environment write on [{$model}]: row belongs to [{$actual}], acting as [{$expected}].");
    }
}
