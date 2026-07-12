<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Exceptions;

use RuntimeException;

final class InvalidMagicLink extends RuntimeException
{
    public static function make(): self
    {
        return new self('The magic link is invalid, expired or has already been used.');
    }
}
