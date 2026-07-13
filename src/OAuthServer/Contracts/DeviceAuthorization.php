<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Contracts;

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\DeviceAuthorizationResult;
use Cbox\Id\OAuthServer\ValueObjects\DeviceGrant;

interface DeviceAuthorization
{
    /**
     * Begin a device grant: issue a device_code + user_code (RFC 8628 §3.2).
     *
     * @param  list<string>  $scopes
     */
    public function request(Client $client, array $scopes): DeviceAuthorizationResult;

    /**
     * Approve a pending grant identified by its user_code, binding the user who
     * consented at the verification URI. Returns false if the code is unknown,
     * expired or not pending.
     */
    public function approve(string $userCode, string $userId, ?string $organizationId): bool;

    /**
     * Deny a pending grant. Returns false if the code is unknown/expired.
     */
    public function deny(string $userCode): bool;

    /**
     * Poll for the token (RFC 8628 §3.4). Returns the approved grant, or throws:
     * DeviceAuthorizationPending, DeviceSlowDown, DeviceAccessDenied,
     * DeviceExpired, or InvalidGrant (unknown device_code).
     */
    public function redeem(string $clientId, string $deviceCode): DeviceGrant;
}
