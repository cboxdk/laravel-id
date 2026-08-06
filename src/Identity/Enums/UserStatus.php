<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Enums;

enum UserStatus: string
{
    case Active = 'active';
    case Disabled = 'disabled';
    case Locked = 'locked';
}
