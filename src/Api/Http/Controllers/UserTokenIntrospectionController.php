<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /user-tokens/introspect` — RFC 7662-shaped introspection for user API
 * tokens (`cbid_pat_…`), for relying-party services that accept them as API
 * credentials. Protected like OAuth introspection: the caller authenticates
 * with an environment API key, otherwise the endpoint is an open oracle for
 * probing token validity.
 *
 * Ownership guard: a caller may only introspect tokens of its own
 * environment — anything else answers `active: false`, never an error.
 */
class UserTokenIntrospectionController
{
    public function __invoke(Request $request, EnvironmentApiKeys $keys, UserApiTokens $tokens): JsonResponse
    {
        $bearer = $request->bearerToken();
        $caller = ($bearer === null || $bearer === '') ? null : $keys->resolve($bearer);

        if ($caller === null) {
            return response()->json(['error' => 'invalid_client'], 401, ['WWW-Authenticate' => 'Bearer realm="introspection"']);
        }

        $token = $tokens->resolve($request->string('token')->toString());

        if ($token === null || $token->environment_id !== $caller->environment_id) {
            return response()->json(['active' => false]);
        }

        return response()->json([
            'active' => true,
            'sub' => $token->user_id,
            'org' => $token->organization_id,
            'scope' => $token->scope->value,
            'families' => $token->resource_families,
            'name' => $token->name,
            'iat' => $token->created_at?->getTimestamp(),
            'exp' => $token->expires_at?->getTimestamp(),
        ]);
    }
}
