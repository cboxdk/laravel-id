<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use RuntimeException;

/**
 * A privileged account operation was attempted for an account that is not active
 * (suspended/delinquent). The account's own auth surfaces already refuse it; this
 * is the defence-in-depth guard on the write path itself.
 */
final class AccountSuspended extends RuntimeException
{
    public static function make(string $accountId): self
    {
        return new self("Account [{$accountId}] is not active.");
    }
}
