<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

final class InvalidPasswordReset extends RuntimeException
{
    public static function make(): self
    {
        return new self('The password-reset link is invalid or has expired.');
    }
}
