<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Contracts\PushedAuthorizationRequests;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Support\ResourceParameter;
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
        private readonly AudienceResolver $audiences,
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

        // RFC 8707 at the back channel: the resource this authorization is FOR is checked
        // here, where the client can be told, rather than surfacing as a dead consent
        // screen after the person has already signed in. Several values, a malformed one,
        // or one this client may not be audienced to are `invalid_target`; scopes that
        // cannot ride on that audience are `invalid_scope`. The resolver is the same one
        // the token endpoint will ask, so PAR cannot accept what redemption would refuse.
        try {
            $resource = ResourceParameter::fromRequest($request);
            // Capped at the client's registration first, as the issuer caps them: a scope
            // the client never registered is /authorize's `invalid_scope` to report.
            $scopes = array_values(array_filter($this->scopes($params['scope'] ?? null), $client->allows(...)));
            $this->audiences->resolve($client, $scopes, $resource);
        } catch (InvalidAudience $e) {
            return $this->error($e->error, 400, $e->getMessage());
        }

        // Stored as the single value just validated, so the consuming /authorize reads
        // exactly what was checked here and never a collapsed repeated key.
        unset($params['resource']);

        if ($resource !== null) {
            $params['resource'] = $resource;
        }

        $pushed = $this->par->push($client, $params);

        return new JsonResponse($pushed, 201);
    }

    /**
     * @return list<string>
     */
    private function scopes(mixed $scope): array
    {
        return is_string($scope)
            ? array_values(array_filter(explode(' ', $scope), static fn (string $s): bool => $s !== ''))
            : [];
    }

    private function error(string $error, int $status, ?string $description = null): JsonResponse
    {
        $body = ['error' => $error];

        if ($description !== null && $description !== '') {
            $body['error_description'] = $description;
        }

        return new JsonResponse($body, $status);
    }
}
