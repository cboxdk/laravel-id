<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
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
    public function __construct(private readonly ClientAuthenticator $clientAuth) {}

    public function __invoke(Request $request, TokenIntrospector $introspector): JsonResponse
    {
        $caller = $this->clientAuth->authenticateConfidential($request);

        if ($caller === null) {
            return response()->json(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Basic realm="introspection"']);
        }

        $callerId = $caller->client_id;

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
}
