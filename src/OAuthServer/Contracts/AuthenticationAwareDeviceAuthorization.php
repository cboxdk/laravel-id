<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;

/**
 * Device approval that records the authentication of the consenting user.
 *
 * Kept separate so existing hosts implementing DeviceAuthorization remain compatible.
 * Hosts supply their verified session's time and methods, never values from the device
 * request or an assurance level inferred from clicking Approve. The original approve()
 * remains contextless; old grants must not acquire assurance after an upgrade.
 */
interface AuthenticationAwareDeviceAuthorization extends DeviceAuthorization
{
    public function approveAuthenticated(
        string $userCode,
        string $userId,
        ?string $organizationId,
        AuthenticationEvent $authentication,
    ): bool;
}
