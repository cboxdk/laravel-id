<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Enums;

enum OperationStatus: string
{
    case Pending = 'pending';
    case Delivered = 'delivered';
    case Failed = 'failed';
    /** Terminal: retries exhausted (dead-lettered) — never attempted again. */
    case Exhausted = 'exhausted';
}
