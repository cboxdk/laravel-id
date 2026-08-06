<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Exceptions;

use RuntimeException;

class UnknownSodPolicy extends RuntimeException
{
    public static function forId(string $policyId): self
    {
        return new self(sprintf('No SoD policy [%s] in this environment.', $policyId));
    }
}
