<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Enums;

enum ActionEndpointStatus: string
{
    case Active = 'active';
    case Paused = 'paused';
}
