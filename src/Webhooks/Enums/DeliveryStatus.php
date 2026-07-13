<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Enums;

enum DeliveryStatus: string
{
    case Pending = 'pending';
    case Delivered = 'delivered';
    case Failed = 'failed';
    /** Terminal: retries exhausted (dead-lettered) — never retried again. */
    case Exhausted = 'exhausted';
}
