<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Enums;

enum ReviewDecision: string
{
    case Pending = 'pending';
    case Certified = 'certified';
    case Revoked = 'revoked';
}
