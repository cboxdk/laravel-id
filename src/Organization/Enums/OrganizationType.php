<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

/**
 * An organization is a tenant. Its type shapes the management hierarchy: a
 * reseller manages customer orgs beneath it in the tree.
 */
enum OrganizationType: string
{
    case Customer = 'customer';
    case Reseller = 'reseller';
}
