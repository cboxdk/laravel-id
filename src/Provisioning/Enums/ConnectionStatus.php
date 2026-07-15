<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Enums;

enum ConnectionStatus: string
{
    case Active = 'active';
    case Paused = 'paused';
}
