<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Exceptions;

use Cbox\AuditChain\Exceptions\CannotCheckpointEmptyChain;

/**
 * A {@see CannotCheckpointEmptyChain} (still a RuntimeException), so it can be caught
 * either as the platform's exception or as the audit-chain package's.
 */
class CannotCheckpointEmptyScope extends CannotCheckpointEmptyChain
{
    public static function make(string $scope): self
    {
        return new self("Cannot checkpoint scope [{$scope}]: it has no audit entries yet.");
    }
}
