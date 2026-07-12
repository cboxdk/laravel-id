<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

enum MembershipStatus: string
{
    case Active = 'active';
    case Invited = 'invited';
    case Suspended = 'suspended';
}
