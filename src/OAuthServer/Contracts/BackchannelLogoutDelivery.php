<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\ValueObjects\LogoutDeliveryOutcome;
use Cbox\Id\OAuthServer\ValueObjects\LogoutNotice;

/**
 * Sends one logout token to one relying party (Back-Channel Logout 1.0 §2.5) and says
 * what happened. It never throws for a relying party's failure — the outcome carries it,
 * and the caller decides whether to try again.
 */
interface BackchannelLogoutDelivery
{
    public function deliver(LogoutNotice $notice): LogoutDeliveryOutcome;
}
