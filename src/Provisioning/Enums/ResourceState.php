<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Enums;

/**
 * The last-known state of a platform user's mirror on a downstream app.
 */
enum ResourceState: string
{
    case Active = 'active';
    case Deactivated = 'deactivated';
    /** The remote record was deleted (DELETE de-provision policy). */
    case Deprovisioned = 'deprovisioned';
}
