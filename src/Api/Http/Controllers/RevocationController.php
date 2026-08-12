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
        // `authenticate()`, NOT `authenticateConfidential()`. Revocation has a public-client
        // mode and this endpoint refused it: a PKCE client authenticates with `none`, so it
        // holds no secret, so every sign-out that tried to revoke its refresh token was
        // answered `401 invalid_client`. Every mainstream browser SDK swallows that failure
        // quietly — so a user pressed "sign out" and their refresh token stayed valid for
        // its whole lifetime, on a deployment whose own discovery document advertises
        // `none` as a supported client-authentication method.
        //
        // Nothing is weakened by allowing it. RFC 7009 §2.1 scopes a revocation to the
        // calling client, which `$callerId` below enforces, so the only new capability is
        // "destroy a token you are already holding" — which is what the endpoint is for.
        // Introspection stays confidential-only: that one ANSWERS QUESTIONS about a token
        // rather than destroying it, and an unauthenticated answer is an oracle.
        $caller = $this->clientAuth->authenticate($request);

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
