<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

class InvalidEmailVerification extends RuntimeException
{
    public static function make(): self
    {
        return new self('The email-verification link is invalid or has expired.');
    }
}
