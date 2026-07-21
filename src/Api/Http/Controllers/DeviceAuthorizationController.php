<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Support\GrantPolicy;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/device_authorization` — the device authorization endpoint
 * (RFC 8628 §3.1). An input-constrained device (TV, CLI) starts a grant here and
 * shows the returned `user_code` + `verification_uri` to the user, then polls the
 * token endpoint with the `device_code` until the user approves on a second device.
 */
class DeviceAuthorizationController
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly DeviceAuthorization $device,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $client = $this->clients->byClientId($request->string('client_id')->toString());

        if ($client === null) {
            return new JsonResponse(['error' => 'invalid_client'], 401);
        }

        // Enforce the registered grant at INITIATION, not only at redemption: otherwise a
        // client that can never complete this flow still creates its state and puts a
        // prompt in front of a user.
        if (! GrantPolicy::allows($client, 'urn:ietf:params:oauth:grant-type:device_code')) {
            return new JsonResponse(['error' => 'unauthorized_client'], 400);
        }

        $scope = $request->string('scope')->toString();
        $scopes = $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));

        $result = $this->device->request($client, $scopes);

        return new JsonResponse([
            'device_code' => $result->deviceCode,
            'user_code' => $result->userCode,
            'verification_uri' => $result->verificationUri,
            'verification_uri_complete' => $result->verificationUriComplete,
            'expires_in' => $result->expiresIn,
            'interval' => $result->interval,
        ]);
    }
}
