<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

use Cbox\Id\Organization\DatabaseEnvironmentResolver;

/**
 * The serving state of a tenant environment. Only an Active environment resolves
 * and serves traffic; a Suspended one is refused by {@see DatabaseEnvironmentResolver}
 * (a kill-switch independent of the owning account's own suspension).
 */
enum EnvironmentStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';

    /** Whether an environment in this state may resolve and serve requests. */
    public function canServe(): bool
    {
        return $this === self::Active;
    }
}
