<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Kernel\Authorization\Contracts\PolicyDecisionPoint;
use Cbox\Id\Kernel\Authorization\ValueObjects\EntitlementValue;
use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Kernel\Authorization\ValueObjects\Subject;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Dpop\DpopResourceGuard;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
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
class DecisionController
{
    /** Checks per request, per field, before the endpoint refuses with 422. */
    private const DEFAULT_MAX_BATCH = 50;

    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly PolicyDecisionPoint $pdp,
        private readonly DpopResourceGuard $dpop,
        private readonly IssuerResolver $issuers,
    ) {}

    /**
     * The scope a caller must hold, once the deployment requires one.
     *
     * Off by default and not because it should be: this endpoint has been served without
     * a scope requirement, so turning it on unannounced would break every existing
     * integration at once. Operators opt in with `cbox-id.oauth.decisions.require_scope`,
     * and the endpoint tells a refused caller exactly which scope to request rather than
     * answering a bare 403.
     */
    private const SCOPE = 'decisions:read';

    public function __invoke(Request $request): JsonResponse
    {
        $token = $this->dpop->bearer($request);

        if (! is_string($token) || $token === '') {
            return $this->refuse('invalid_token', 'no access token was presented');
        }

        $introspection = $this->introspector->introspect($token);

        if (! $introspection->active) {
            return $this->refuse('invalid_token', 'the access token is expired or revoked');
        }

        // Sender-constrained tokens must arrive with a matching DPoP proof.
        try {
            $this->dpop->enforce($request, $token, $introspection);
        } catch (InvalidDpopProof) {
            return $this->refuse('invalid_token', 'the DPoP proof is missing or does not match this token', scheme: 'DPoP');
        }

        // Least-privilege, matching UserInfo. A token minted for a specific RFC 8707
        // resource must not be replayable here — and this endpoint answers with strictly
        // MORE than UserInfo does: the subject's whole permission and entitlement set in
        // the organization. UserInfo has refused a wrong-audience token for some time,
        // with a docblock explaining why; this one had neither that check nor a scope.
        if (! $introspection->isAudience($this->issuers->issuer())) {
            return $this->refuse('invalid_token', 'the access token was not issued for this endpoint');
        }

        if (config('cbox-id.oauth.decisions.require_scope') === true
            && ! $introspection->hasScope(self::SCOPE)) {
            return $this->refuse(
                'insufficient_scope',
                'the access token must carry the "'.self::SCOPE.'" scope',
                403,
            );
        }

        $sub = (string) $introspection->subject;
        $org = $introspection->claims['org'] ?? null;

        if (! is_string($org) || $org === '') {
            return new JsonResponse(['error' => 'no_organization_context'], 422);
        }

        // A client_credentials token's subject is the client itself (a service).
        $subject = $sub === $introspection->clientId ? Subject::service($sub) : Subject::user($sub);

        // Bound the batch BEFORE any of it is evaluated. Each permission check walks
        // the relationship graph to MAX_DEPTH with two queries per node, so an
        // unbounded array turns one authenticated HTTP request into an arbitrary
        // number of database round trips — a self-inflicted amplification any holder
        // of a valid token could aim at the decision plane.
        $limit = $this->batchLimit();

        foreach (['permissions', 'entitlements'] as $field) {
            if (count($this->list($request->input($field))) > $limit) {
                return new JsonResponse([
                    'error' => 'batch_too_large',
                    'error_description' => "at most {$limit} {$field} may be checked in one request",
                ], 422);
            }
        }

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

        // Memoized per REQUEST, not per instance-lifetime: this controller is
        // constructed fresh for each request, so the array cannot outlive it even in
        // a long-lived worker. That distinction matters — a memo held on one of this
        // codebase's singletons is exactly how three separate cross-environment bugs
        // were introduced (DatabaseEventBus, DatabaseAuditLog, DatabaseKeyManager).
        //
        // Within one batch the org and subject are fixed, so a repeated
        // (relation, resource) pair can only produce the same answer — and clients
        // batching a screen's worth of checks repeat pairs constantly.
        /** @var array<string, bool> $memo */
        $memo = [];

        foreach ($this->list($request->input('permissions')) as $check) {
            if (! is_array($check)) {
                continue;
            }

            $relation = $check['relation'] ?? null;
            $resource = $check['resource'] ?? null;

            if (! is_string($relation) || ! is_string($resource) || $relation === '' || $resource === '') {
                continue;
            }

            $key = $relation."\0".$resource;

            $out[] = [
                'relation' => $relation,
                'resource' => $resource,
                'allowed' => $memo[$key] ??= $this->pdp->can($org, $subject, $relation, $this->ref($resource)),
            ];
        }

        return $out;
    }

    /**
     * The most checks one request may ask for. Configurable because the right
     * number depends on how a deployment's clients batch, but never unbounded.
     */
    private function batchLimit(): int
    {
        $limit = config('cbox-id.oauth.decisions.max_batch', self::DEFAULT_MAX_BATCH);

        return is_numeric($limit) ? max(1, (int) $limit) : self::DEFAULT_MAX_BATCH;
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

    /**
     * A refusal a client can act on.
     *
     * Three distinct causes — no token, an inactive one, a bad DPoP proof — used to emit
     * the same bare `{"error":"invalid_token"}` with no description and, on two of the
     * three, no `WWW-Authenticate` at all. RFC 6750 §3 makes that header a MUST, and
     * TokenController already solved this one file over, with a docblock noting that
     * several real client libraries treat a bare 401 as fatal.
     */
    private function refuse(string $error, string $description, int $status = 401, string $scheme = 'Bearer'): JsonResponse
    {
        $headers = $status === 401
            ? ['WWW-Authenticate' => $scheme.' error="'.$error.'", error_description="'.$description.'"']
            : [];

        return new JsonResponse(['error' => $error, 'error_description' => $description], $status, $headers);
    }
}
