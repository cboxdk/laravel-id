<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Audit\Enums;

enum ActorType: string
{
    case User = 'user';
    case Service = 'service';
    case System = 'system';
    case Operator = 'operator';
    case AccountMember = 'account_member';
}
