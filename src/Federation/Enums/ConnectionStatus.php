<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Enums;

enum ConnectionStatus: string
{
    case Draft = 'draft';
    case Active = 'active';
    case Inactive = 'inactive';
}
