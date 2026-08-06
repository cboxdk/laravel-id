<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Exceptions;

use RuntimeException;

class SlugAlreadyTaken extends RuntimeException
{
    public static function make(string $slug): self
    {
        return new self("An organization with the slug [{$slug}] already exists.");
    }
}
