<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * The connection does not exist in this environment — or, on a person's own path, it is
 * not theirs, which answers the same way so one person cannot probe another's.
 */
class PipeConnectionNotFound extends RuntimeException
{
    public static function make(): self
    {
        return new self('No such connected account.');
    }
}
