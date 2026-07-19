<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Dpop\DpopResourceGuard;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Cbox\Id\Organization\Contracts\Organizations;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `GET|POST /oauth/userinfo` — the OIDC UserInfo endpoint (OpenID Connect Core
 * §5.3). Authenticated by the access token (Bearer, or DPoP for a
 * sender-constrained token); returns claims about the end-user, gated by the
 * token's granted scopes (`profile` → name, `email` → email). Requires the
 * `openid` scope.
 */
final class UserInfoController
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly Subjects $subjects,
        private readonly DpopResourceGuard $dpop,
        private readonly Organizations $organizations,
        private readonly AccessChecker $access,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $bearer = $this->dpop->bearer($request);

        if (! is_string($bearer) || $bearer === '') {
            return $this->challenge('missing access token');
        }

        $token = $this->introspector->introspect($bearer);

        if (! $token->active || ! $token->hasScope('openid') || $token->subject === null) {
            return $this->challenge('the access token is invalid or lacks the openid scope');
        }

        // A sender-constrained (cnf.jkt) token requires a valid DPoP proof over
        // this request and this exact token — a stolen bearer alone is rejected.
        try {
            $this->dpop->enforce($request, $bearer, $token);
        } catch (InvalidDpopProof $e) {
            return $this->challenge($e->getMessage(), scheme: 'DPoP');
        }

        $claims = ['sub' => $token->subject];
        $subject = $this->subjects->find($token->subject);

        if ($subject !== null) {
            if ($token->hasScope('email') && $subject->email !== null) {
                $claims['email'] = $subject->email;
            }

            if ($token->hasScope('profile') && $subject->name !== null) {
                $claims['name'] = $subject->name;
            }
        }

        // The org id travels in the token's `org` claim; resolve its name so a
        // relying party can display the organization, not an opaque id.
        $orgId = $token->claims['org'] ?? null;
        if (is_string($orgId) && $orgId !== '') {
            $claims['org'] = $orgId;
            $orgName = $this->organizations->find($orgId)?->name;
            if (is_string($orgName) && $orgName !== '') {
                $claims['org_name'] = $orgName;
            }

            // RBAC (federated model): mirror the access token's `roles`/`permissions`
            // claims here so a relying party that authenticates via id_token + UserInfo
            // (the standard SDK login flow) receives the same signal a resource server
            // reads from the JWT. Same scoping as issuance: the token's client's own
            // declared roles plus org-wide roles, never another app's.
            if ($token->clientId !== null) {
                $rbac = $this->access->forToken($token->subject, $orgId, $token->clientId);
                if (! $rbac->isEmpty()) {
                    $claims['roles'] = $rbac->roles;
                    $claims['permissions'] = $rbac->permissions;
                }
            }
        }

        return new JsonResponse($claims);
    }

    private function challenge(string $description, string $scheme = 'Bearer'): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'invalid_token', 'error_description' => $description],
            401,
            ['WWW-Authenticate' => $scheme.' error="invalid_token"'],
        );
    }
}
