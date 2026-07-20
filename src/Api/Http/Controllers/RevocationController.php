<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/revoke` — OAuth 2.0 Token Revocation (RFC 7009). The caller
 * authenticates as a registered client, then submits an access or refresh token
 * to invalidate. Per §2.2 the endpoint returns 200 regardless of whether the
 * token existed, so it is not an existence oracle.
 */
class RevocationController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly TokenIntrospector $introspector,
        private readonly RefreshTokens $refreshTokens,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $caller = $this->clientAuth->authenticateConfidential($request);

        if ($caller === null) {
            return new JsonResponse(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Basic realm="revocation"']);
        }

        $callerId = $caller->client_id;

        $token = $request->string('token')->toString();

        if ($token !== '') {
            // A refresh token revokes its whole rotation family; an access token
            // is revoked by its jti. Both are scoped to the caller (RFC 7009 §2.1):
            // a client can only revoke tokens issued to itself. Unknown or
            // other-owned tokens are a silent no-op (still 200, no oracle).
            $this->refreshTokens->revoke($token, $callerId);

            $introspected = $this->introspector->introspect($token);
            $jti = $introspected->claims['jti'] ?? null;

            if ($introspected->active && $introspected->clientId === $callerId && is_string($jti)) {
                $this->introspector->revoke($jti);
            }
        }

        return new JsonResponse([]);
    }
}
