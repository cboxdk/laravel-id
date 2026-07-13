<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\PushedAuthorizationRequests;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/par` — the Pushed Authorization Request endpoint (RFC 9126). The
 * client authenticates and submits its authorization request parameters directly
 * (back-channel), receiving a single-use `request_uri` to put on the front-channel
 * `/authorize` redirect. This keeps request parameters off the browser URL and
 * lets the AS fix them before user interaction — the foundation FAPI builds on.
 */
final class PushedAuthorizationController
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly PushedAuthorizationRequests $par,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $client = $this->clients->byClientId($request->string('client_id')->toString());

        // Confidential clients authenticate with their secret; public clients (PKCE)
        // may push without one. An unknown or mis-authenticated client is refused.
        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        if ($client->secret_hash !== null
            && ! $this->clients->verifySecret($client, $request->string('client_secret')->toString())) {
            return $this->error('invalid_client', 401);
        }

        $params = $request->except(['client_secret']);

        if (($params['response_type'] ?? null) !== 'code') {
            return $this->error('invalid_request', 400);
        }

        $pushed = $this->par->push($client, $params);

        return new JsonResponse($pushed, 201);
    }

    private function error(string $error, int $status): JsonResponse
    {
        return new JsonResponse(['error' => $error], $status);
    }
}
