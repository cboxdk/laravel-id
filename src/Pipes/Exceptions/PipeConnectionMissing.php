<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * The person has not connected this provider. Said only to an app that is granted the
 * pipe — it is the app's cue to show a "Connect" button, which it cannot do if a missing
 * connection looks the same as a refusal.
 */
class PipeConnectionMissing extends RuntimeException
{
    public static function make(): self
    {
        return new self('The user has not connected this provider.');
    }
}
