<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Exceptions;

use RuntimeException;
use Throwable;

/**
 * The append could not claim a free position in the chain within its attempt budget.
 *
 * Thrown rather than swallowed on purpose: an entry that cannot be written is a hole
 * in a tamper-evident trail, and a hole is indistinguishable from a deletion when
 * someone later runs verifyChain(). The caller must see it.
 */
class CannotAppendToAuditChain extends RuntimeException
{
    public static function afterAttempts(string $scope, int $attempts, Throwable $previous): self
    {
        return new self(
            "Could not append to audit chain [{$scope}]: the next sequence was taken by a concurrent writer on all {$attempts} attempts.",
            0,
            $previous,
        );
    }
}
