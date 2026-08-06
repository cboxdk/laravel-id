<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

/**
 * A platform operator's status. `Suspended` revokes operator (platform-staff)
 * access, so it is a typed enum rather than a raw string.
 */
enum OperatorStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
}
