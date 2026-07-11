<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Enums;

/**
 * Where an entitlement's authoritative value comes from. Central ID stores a
 * projection; the source (billing, an app, a human) is the system of record.
 */
enum EntitlementSource: string
{
    case Billing = 'billing';
    case Manual = 'manual';
    case System = 'system';
}
