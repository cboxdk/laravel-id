<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Enums;

/**
 * Where a request to approve one action stands, as the host asking for it sees it.
 */
enum ActionApprovalStatus: string
{
    /** Waiting for the person. */
    case Pending = 'pending';

    /** Approved and not yet spent: the host may run the action once. */
    case Approved = 'approved';

    case Denied = 'denied';

    /** Nobody answered in time, or it was approved but never spent before it lapsed. */
    case Expired = 'expired';

    /** Spent: the action it approved has run. */
    case Consumed = 'consumed';
}
