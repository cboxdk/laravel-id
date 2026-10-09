<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * The connection exists but its tokens no longer work and cannot be refreshed: the
 * provider refused the refresh token, or the access token expired with nothing to
 * refresh it with. Only the person can fix this, by connecting again.
 */
class PipeReauthorizationRequired extends RuntimeException
{
    public static function make(): self
    {
        return new self('The user must connect this provider again.');
    }
}
