<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Exceptions;

use RuntimeException;

class CannotCheckpointEmptyScope extends RuntimeException
{
    public static function make(string $scope): self
    {
        return new self("Cannot checkpoint scope [{$scope}]: it has no audit entries yet.");
    }
}
