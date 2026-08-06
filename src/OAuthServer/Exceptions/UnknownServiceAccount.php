<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

class UnknownServiceAccount extends RuntimeException
{
    public static function make(string $clientId): self
    {
        return new self("No service account for client [{$clientId}].");
    }
}
