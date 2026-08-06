<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Enums;

enum DirectoryStatus: string
{
    case Active = 'active';
    case Paused = 'paused';
}
