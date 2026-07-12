<?php

declare(strict_types=1);

namespace Cbox\Id\Organization\Enums;

enum OrganizationStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
    case Deleted = 'deleted';
}
