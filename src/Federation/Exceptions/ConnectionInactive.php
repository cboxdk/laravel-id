<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

final class ConnectionInactive extends RuntimeException
{
    public static function make(string $connectionId): self
    {
        return new self("Connection [{$connectionId}] is not active; refusing to complete login.");
    }
}
