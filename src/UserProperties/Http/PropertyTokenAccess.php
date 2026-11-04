<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Http;

use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Dpop\DpopResourceGuard;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

class PropertyTokenAccess
{
    public function __construct(
        private readonly TokenIntrospector $tokens,
        private readonly DpopResourceGuard $dpop,
        private readonly IssuerResolver $issuers,
    ) {}

    public function client(Request $request, string $userId): string
    {
        $bearer = $this->dpop->bearer($request);
        if (! is_string($bearer) || $bearer === '') {
            throw new UnauthorizedHttpException('Bearer', 'An access token is required.');
        }
        $token = $this->tokens->introspect($bearer);
        if (! $token->active || $token->clientId === null || $token->subject === null || ! $token->isAudience($this->issuers->issuer())) {
            throw new UnauthorizedHttpException('Bearer', 'Invalid access token.');
        }
        try {
            $this->dpop->enforce($request, $bearer, $token);
        } catch (InvalidDpopProof $e) {
            throw new UnauthorizedHttpException('DPoP', $e->getMessage());
        }
        // A delegated token can only address its own subject. Machine tokens are
        // explicitly granted access by an operator through the namespace registry.
        if ($token->subject !== $userId && $token->subject !== $token->clientId) {
            throw new AccessDeniedHttpException('This token cannot act for another user.');
        }
        $scope = $request->isMethod('GET') ? 'user_properties:read' : 'user_properties:write';
        if (! $token->hasScope($scope)) {
            throw new AccessDeniedHttpException('Missing '.$scope.' scope.');
        }

        return $token->clientId;
    }
}
