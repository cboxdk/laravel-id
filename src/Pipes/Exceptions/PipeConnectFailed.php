<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Exceptions;

use RuntimeException;

/**
 * Connecting an account did not complete. `reason` is a stable, machine-readable code a
 * hosted page can translate; the message never carries a code, a token or the provider's
 * raw response body.
 *
 *  - `state_mismatch` — the callback does not belong to the flow this browser started
 *  - `pipe_unavailable` — the pipe was removed or disabled while the person was away
 *  - `exchange_failed` — the provider refused the code, or could not be reached
 */
class PipeConnectFailed extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct("Connecting the account failed ({$reason}).");
    }

    public static function because(string $reason): self
    {
        return new self($reason);
    }
}
