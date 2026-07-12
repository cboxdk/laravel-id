<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Enums;

enum EndpointStatus: string
{
    case Active = 'active';
    case Paused = 'paused';
}
