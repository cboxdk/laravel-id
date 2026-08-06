<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /user-tokens/introspect` — RFC 7662-shaped introspection for user API
 * tokens (`cbid_pat_…`), for relying-party services that accept them as API
 * credentials. Protected like OAuth introspection: the caller authenticates
 * with an environment API key, otherwise the endpoint is an open oracle for
 * probing token validity.
 *
 * AUTHORIZATION. Authenticating is not enough. A successful response discloses
 * the token's subject, its organization and its human-readable name — user data,
 * about any user in the environment — so the caller must additionally carry
 * `users:read`, the same scope that gates `GET /users`. Without that check this
 * endpoint let a deliberately narrow key (a directory-sync key, say) enumerate
 * the identity behind every personal access token in the environment: a
 * capability it was never granted.
 *
 * A caller missing the scope gets 403 `insufficient_scope`, NOT `active: false`.
 * That distinction is deliberate. The no-oracle rule protects facts about the
 * TOKEN, and this 403 is decided before the token is looked at at all — it is a
 * constant function of the caller's own key, which the caller already knows, so
 * it discloses nothing an attacker could not derive by asking about a token they
 * minted themselves. Answering `active: false` would hide no more and cost more:
 * a relying party would silently treat every valid credential its users hold as
 * dead, reading a misconfiguration as a fleet-wide revocation.
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

        $required = EnvironmentApiScope::UsersRead;

        if (! $caller->can($required)) {
            return response()->json(
                ['error' => 'insufficient_scope', 'scope' => $required->value],
                403,
                ['WWW-Authenticate' => sprintf(
                    'Bearer realm="introspection", error="insufficient_scope", scope="%s"',
                    $required->value,
                )],
            );
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
            // null = unrestricted (every family); a list = exactly those families;
            // and now [] = a token restricted to no family at all, a state the
            // previous array-shaped storage could not represent.
            'families' => $token->resource_families->toStorage(),
            'name' => $token->name,
            'iat' => $token->created_at?->getTimestamp(),
            'exp' => $token->expires_at?->getTimestamp(),
        ]);
    }
}
