<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Enums;

enum CampaignStatus: string
{
    case Open = 'open';
    case Closed = 'closed';
}
