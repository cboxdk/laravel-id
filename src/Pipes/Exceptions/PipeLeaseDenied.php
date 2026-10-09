<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * Uniform refusal on the lease path for an app that may not lease this pipe's tokens:
 * no such pipe, a disabled pipe, or no grant for the app. One exception, one message, so
 * an app learns nothing about which pipes exist from being refused. The precise reason
 * is audited (`pipe.lease.denied`), never returned.
 *
 * An app that IS granted the pipe is told more, because it needs to: see
 * {@see PipeConnectionMissing} and {@see PipeReauthorizationRequired}.
 */
class PipeLeaseDenied extends RuntimeException
{
    public static function make(): self
    {
        return new self('Lease denied.');
    }
}
