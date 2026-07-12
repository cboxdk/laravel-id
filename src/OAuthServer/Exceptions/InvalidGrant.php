<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Exceptions;

use RuntimeException;

final class InvalidGrant extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('invalid_grant: '.$reason);
    }
}
