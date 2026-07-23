<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

use Cbox\Id\Platform\Models\Account;

/**
 * An account's lifecycle status. `Suspended` is an access-revocation state — console
 * login and API access gate on {@see Account::isActive()} —
 * so it is an enum, not a raw string, to keep suspension checks typo-proof and
 * exhaustive, consistent with the other modules' status enums.
 */
enum AccountStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
}
