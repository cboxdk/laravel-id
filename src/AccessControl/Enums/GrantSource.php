<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Enums;

enum GrantSource: string
{
    case Manual = 'manual';
    case Pushed = 'pushed';
    case System = 'system';
}
