<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `GET|POST /oauth/userinfo` — the OIDC UserInfo endpoint (OpenID Connect Core
 * §5.3). Authenticated by the access token as a bearer; returns claims about the
 * end-user, gated by the token's granted scopes (`profile` → name, `email` →
 * email). Requires the `openid` scope.
 */
final class UserInfoController
{
    public function __construct(
        private readonly TokenIntrospector $introspector,
        private readonly Subjects $subjects,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $bearer = $request->bearerToken();

        if (! is_string($bearer) || $bearer === '') {
            return $this->challenge('missing access token');
        }

        $token = $this->introspector->introspect($bearer);

        if (! $token->active || ! $token->hasScope('openid') || $token->subject === null) {
            return $this->challenge('the access token is invalid or lacks the openid scope');
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

        return new JsonResponse($claims);
    }

    private function challenge(string $description): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'invalid_token', 'error_description' => $description],
            401,
            ['WWW-Authenticate' => 'Bearer error="invalid_token"'],
        );
    }
}
