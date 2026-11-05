<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

class TotpDeviceRefused extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct($reason);
    }
}
