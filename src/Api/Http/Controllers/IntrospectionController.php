<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/introspect` — RFC 7662 token introspection. The endpoint is
 * protected: the caller must authenticate as a registered client (RFC 7662 §2.1),
 * otherwise it becomes an open oracle for probing token validity.
 */
final class IntrospectionController
{
    public function __construct(private readonly ClientRegistry $clients) {}

    public function __invoke(Request $request, TokenIntrospector $introspector): JsonResponse
    {
        $callerId = $this->authenticatedClientId($request);

        if ($callerId === null) {
            return response()->json(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Basic realm="introspection"']);
        }

        $result = $introspector->introspect($request->string('token')->toString());

        // Ownership (RFC 7662 §2.1): a client may only introspect its own tokens.
        // Anything else answers `active: false` so the endpoint isn't an oracle
        // for probing other clients' tokens.
        if (! $result->active || $result->clientId !== $callerId) {
            return response()->json(['active' => false]);
        }

        return response()->json([
            'active' => true,
            'sub' => $result->subject,
            'client_id' => $result->clientId,
            'scope' => implode(' ', $result->scopes),
        ]);
    }

    /**
     * The authenticated client's id via HTTP Basic (preferred) or form body
     * credentials, verified in constant time — or null when missing/invalid.
     */
    private function authenticatedClientId(Request $request): ?string
    {
        $clientId = $request->getUser() ?? $request->string('client_id')->toString();
        $secret = $request->getPassword() ?? $request->string('client_secret')->toString();

        if ($clientId === '') {
            return null;
        }

        $client = $this->clients->byClientId($clientId);

        return $client !== null && $this->clients->verifySecret($client, $secret) ? $client->client_id : null;
    }
}
