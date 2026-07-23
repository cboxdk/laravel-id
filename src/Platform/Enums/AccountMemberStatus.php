<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

use Cbox\Id\Platform\Models\AccountMember;

/**
 * An account member's status. `Invited` is a pending member who has not yet accepted
 * (no console access until then); `Active` is a full member. A typed enum keeps the
 * access gate ({@see AccountMember::isActive()}) exhaustive.
 */
enum AccountMemberStatus: string
{
    case Active = 'active';
    case Invited = 'invited';
}
