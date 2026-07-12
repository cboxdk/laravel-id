<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/introspect` — RFC 7662 token introspection.
 */
final class IntrospectionController
{
    public function __invoke(Request $request, TokenIntrospector $introspector): JsonResponse
    {
        $result = $introspector->introspect($request->string('token')->toString());

        if (! $result->active) {
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
