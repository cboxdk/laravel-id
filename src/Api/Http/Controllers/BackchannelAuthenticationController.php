<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Exceptions\UnknownUserHint;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/backchannel_authentication` — the CIBA backchannel authentication
 * endpoint (OpenID Connect CIBA Core §7). A client (typically an autonomous / AI
 * agent) starts a decoupled authentication here by naming the user with
 * `login_hint`; the user approves out-of-band, and the client then polls the token
 * endpoint with the returned `auth_req_id`.
 */
final class BackchannelAuthenticationController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly BackchannelAuthentication $ciba,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        // The backchannel endpoint is client-authenticated, like the token endpoint.
        $client = $this->clientAuth->authenticate($request);

        if ($client === null) {
            return new JsonResponse(['error' => 'invalid_client'], 401);
        }

        $loginHint = trim($request->string('login_hint')->toString());

        // CIBA Core §7.1: exactly one hint is required to identify the user. We
        // support login_hint; a request with none cannot be fulfilled.
        if ($loginHint === '') {
            return new JsonResponse(['error' => 'invalid_request'], 400);
        }

        $scope = $request->string('scope')->toString();
        $scopes = $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));

        $bindingMessage = $request->string('binding_message')->toString();
        $requestedExpiry = $request->has('requested_expiry') ? $request->integer('requested_expiry') : null;

        try {
            $result = $this->ciba->request(
                $client,
                $scopes,
                $loginHint,
                $bindingMessage !== '' ? $bindingMessage : null,
                null,
                $requestedExpiry,
            );
        } catch (UnknownUserHint) {
            return new JsonResponse(['error' => 'unknown_user_id'], 400);
        }

        // Only the client-facing fields are serialized — never the internal request
        // id the host uses to approve.
        return new JsonResponse([
            'auth_req_id' => $result->authReqId,
            'expires_in' => $result->expiresIn,
            'interval' => $result->interval,
        ]);
    }
}
