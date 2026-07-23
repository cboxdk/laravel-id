<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\Enums;

/**
 * A project's lifecycle status. `Suspended` revokes access to the project's
 * environments, so it is a typed enum rather than a raw string.
 */
enum ProjectStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
}
