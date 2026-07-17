<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Exceptions;

use Cbox\Id\Platform\Models\Account;
use RuntimeException;

/**
 * The account has already provisioned as many environments as its plan allows
 * ({@see Account::$environment_limit}). Raising the
 * limit is a billing/plan change, not something the provisioning path decides —
 * so it is refused here rather than silently exceeded.
 */
final class EnvironmentLimitReached extends RuntimeException
{
    public static function make(string $accountId, int $limit): self
    {
        return new self("Account [{$accountId}] has reached its plan limit of {$limit} environment(s).");
    }
}
