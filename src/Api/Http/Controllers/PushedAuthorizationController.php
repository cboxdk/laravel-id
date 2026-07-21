<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\PushedAuthorizationRequests;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/par` — the Pushed Authorization Request endpoint (RFC 9126). The
 * client authenticates and submits its authorization request parameters directly
 * (back-channel), receiving a single-use `request_uri` to put on the front-channel
 * `/authorize` redirect. This keeps request parameters off the browser URL and
 * lets the AS fix them before user interaction — the foundation FAPI builds on.
 */
class PushedAuthorizationController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly PushedAuthorizationRequests $par,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        // Confidential clients authenticate with their secret; public clients (PKCE)
        // may push without one. An unknown or mis-authenticated client is refused.
        $client = $this->clientAuth->authenticate($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        $params = $request->except(['client_secret']);

        if (($params['response_type'] ?? null) !== 'code') {
            return $this->error('invalid_request', 400);
        }

        // PKCE is mandatory for public clients (OAuth 2.1 / RFC 9700). Enforce it on
        // the back channel too — a public client that pushes without an S256
        // code_challenge is refused here, not only at /authorize.
        if ($client->type === ClientType::Public) {
            $challenge = $params['code_challenge'] ?? null;

            if (! is_string($challenge) || $challenge === '' || ($params['code_challenge_method'] ?? 'S256') !== 'S256') {
                return $this->error('invalid_request', 400);
            }
        }

        $pushed = $this->par->push($client, $params);

        return new JsonResponse($pushed, 201);
    }

    private function error(string $error, int $status): JsonResponse
    {
        return new JsonResponse(['error' => $error], $status);
    }
}
