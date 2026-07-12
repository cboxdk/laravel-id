<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
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
final class RevocationController
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly TokenIntrospector $introspector,
        private readonly RefreshTokens $refreshTokens,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        if (! $this->callerAuthenticated($request)) {
            return new JsonResponse(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Basic realm="revocation"']);
        }

        $token = $request->string('token')->toString();

        if ($token !== '') {
            // A refresh token revokes its whole rotation family; an access token
            // is revoked by its jti. We try both — unknown tokens are a no-op.
            $this->refreshTokens->revoke($token);

            $introspected = $this->introspector->introspect($token);
            $jti = $introspected->claims['jti'] ?? null;

            if ($introspected->active && is_string($jti)) {
                $this->introspector->revoke($jti);
            }
        }

        return new JsonResponse([]);
    }

    private function callerAuthenticated(Request $request): bool
    {
        $clientId = $request->getUser() ?? $request->string('client_id')->toString();
        $secret = $request->getPassword() ?? $request->string('client_secret')->toString();

        if ($clientId === '') {
            return false;
        }

        $client = $this->clients->byClientId($clientId);

        return $client !== null && $this->clients->verifySecret($client, $secret);
    }
}
