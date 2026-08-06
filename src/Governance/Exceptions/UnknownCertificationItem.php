<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Exceptions;

use RuntimeException;

class UnknownCertificationItem extends RuntimeException
{
    public static function forId(string $itemId): self
    {
        return new self(sprintf('No certification item [%s] in this environment.', $itemId));
    }
}
