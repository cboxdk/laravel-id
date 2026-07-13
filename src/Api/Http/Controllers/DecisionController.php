<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Subject;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/decisions` — the authorization decision endpoint (the hot path).
 *
 * A resource server presents the caller's access token and asks, in one round
 * trip, both "may this subject do X on Y?" (permissions / ReBAC) and "does the
 * org have entitlement Z?" (billing-fed projection). Everything is resolved
 * **live** against the decision plane — permissions from the relationship store,
 * entitlements from the version-invalidated hot-path cache — so a revoked role or
 * a cancelled plan takes effect on the very next call. Nothing fast-changing is
 * baked into the token; the token stays a thin identity bearer.
 *
 * Body: `{ "permissions": [{"relation": "...", "resource": "type:id"}], "entitlements": ["plan", ...] }`
 */
final class DecisionController
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly PolicyDecisionPoint $pdp,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $token = $request->bearerToken();

        if (! is_string($token) || $token === '') {
            return new JsonResponse(['error' => 'invalid_token'], 401);
        }

        $introspection = $this->introspector->introspect($token);

        if (! $introspection->active) {
            return new JsonResponse(['error' => 'invalid_token'], 401);
        }

        $sub = (string) $introspection->subject;
        $org = $introspection->claims['org'] ?? null;

        if (! is_string($org) || $org === '') {
            return new JsonResponse(['error' => 'no_organization_context'], 422);
        }

        // A client_credentials token's subject is the client itself (a service).
        $subject = $sub === $introspection->clientId ? Subject::service($sub) : Subject::user($sub);

        return new JsonResponse([
            'subject' => ['type' => $subject->type, 'id' => $subject->id],
            'organization' => $org,
            'permissions' => $this->permissions($request, $org, $subject),
            'entitlements' => $this->entitlements($request, $org),
        ]);
    }

    /**
     * @return list<array{relation: string, resource: string, allowed: bool}>
     */
    private function permissions(Request $request, string $org, Subject $subject): array
    {
        $out = [];

        foreach ($this->list($request->input('permissions')) as $check) {
            if (! is_array($check)) {
                continue;
            }

            $relation = $check['relation'] ?? null;
            $resource = $check['resource'] ?? null;

            if (! is_string($relation) || ! is_string($resource) || $relation === '' || $resource === '') {
                continue;
            }

            $out[] = [
                'relation' => $relation,
                'resource' => $resource,
                'allowed' => $this->pdp->can($org, $subject, $relation, $this->ref($resource)),
            ];
        }

        return $out;
    }

    /**
     * @return array<string, array<string, mixed>|null>
     */
    private function entitlements(Request $request, string $org): array
    {
        $out = [];

        foreach ($this->list($request->input('entitlements')) as $key) {
            if (! is_string($key) || $key === '') {
                continue;
            }

            $value = $this->pdp->entitlement($org, $key);
            $out[$key] = $value instanceof EntitlementValue ? [
                'value' => $value->value,
                'mode' => $value->mode->value,
                'source' => $value->source->value,
                'version' => $value->version,
            ] : null;
        }

        return $out;
    }

    /** Parse a "type:id" reference (everything after the first colon is the id). */
    private function ref(string $resource): ResourceRef
    {
        $pos = strpos($resource, ':');

        return $pos === false
            ? ResourceRef::of($resource, '')
            : ResourceRef::of(substr($resource, 0, $pos), substr($resource, $pos + 1));
    }

    /**
     * @return array<int, mixed>
     */
    private function list(mixed $value): array
    {
        return is_array($value) ? array_values($value) : [];
    }
}
