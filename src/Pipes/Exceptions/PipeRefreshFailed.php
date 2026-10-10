<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * A refresh could not be completed right now — the provider was unreachable, answered a
 * 5xx or 429, refused the CLIENT (a pipe whose secret was rotated at the provider), or
 * another process held the refresh for longer than the caller was willing to wait.
 *
 * Transient by definition: the connection stays `active`, the failure is counted and
 * audited, and the next attempt may succeed. A refusal of the refresh TOKEN itself is not
 * this — it is {@see PipeReauthorizationRequired}.
 */
class PipeRefreshFailed extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct("Refreshing the connection failed ({$reason}).");
    }

    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
