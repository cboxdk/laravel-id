<?php

declare(strict_types=1);

namespace Cbox\Id\Governance\Enums;

/**
 * What happens to items left un-reviewed (pending) when a campaign closes.
 * The default is Revoke: unattested access is removed (deny-by-default posture —
 * access no one vouched for should not silently survive a review).
 */
enum PendingPolicy: string
{
    case Revoke = 'revoke';
    case Certify = 'certify';
}
