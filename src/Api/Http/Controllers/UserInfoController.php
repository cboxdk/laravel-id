<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\Api\Support\IdentityClaims;
use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\FeatureFlags\Support\FeatureFlagClaim;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Dpop\DpopResourceGuard;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Cbox\Id\OAuthServer\ValueObjects\ProtectedResource;
use Cbox\Id\Organization\Contracts\Memberships;
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
class UserInfoController
{
    private readonly IdentityClaims $identity;

    /**
     * The claims come from {@see IdentityClaims}, built from the services this controller
     * is given unless a host hands it one of its own.
     */
    public function __construct(
        private readonly TokenIntrospector $introspector,
        Subjects $subjects,
        private readonly DpopResourceGuard $dpop,
        Organizations $organizations,
        Memberships $memberships,
        AccessChecker $access,
        private readonly IssuerResolver $issuers,
        // Trailing and optional so existing constructions keep compiling.
        ?FeatureFlagClaim $featureFlags = null,
        ?IdentityClaims $identity = null,
    ) {
        $this->identity = $identity ?? new IdentityClaims(
            $subjects,
            $organizations,
            $memberships,
            $access,
            $featureFlags ?? app(FeatureFlagClaim::class),
        );
    }

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

        // Least-privilege: a token minted for a specific resource (RFC 8707) must not
        // be replayable at UserInfo to harvest identity claims. Accept only a token
        // audienced for this issuer (or one carrying no explicit audience).
        if (! $token->isAudience($this->issuers->issuer())) {
            return $this->challenge('the access token was not issued for this endpoint');
        }

        // A sender-constrained (cnf.jkt) token requires a valid DPoP proof over
        // this request and this exact token — a stolen bearer alone is rejected.
        try {
            $this->dpop->enforce($request, $bearer, $token);
        } catch (InvalidDpopProof $e) {
            return $this->challenge($e->getMessage(), scheme: 'DPoP');
        }

        // Beside `sub`, exactly what the ID Token carries for the same grant: both read
        // IdentityClaims, so a relying party that skips this call misses nothing. Read
        // live here; the ID Token is a snapshot from when it was minted.
        $orgId = $token->claims['org'] ?? null;

        $claims = [
            'sub' => $token->subject,
            ...$this->identity->for(
                $token->subject,
                is_string($orgId) ? $orgId : null,
                $token->clientId,
                $token->scopes,
            ),
        ];

        return new JsonResponse($claims);
    }

    private function challenge(string $description, string $scheme = 'Bearer'): JsonResponse
    {
        // RFC 9728 §5.1: name where this resource is described, so a client holding only
        // the endpoint's URL can discover which authorization server to ask.
        $challenge = new BearerChallenge(
            resourceMetadata: ServerMetadata::issuer().ProtectedResource::WELL_KNOWN,
            error: 'invalid_token',
            scheme: $scheme,
        );

        return new JsonResponse(
            ['error' => 'invalid_token', 'error_description' => $description],
            401,
            $challenge->headers(),
        );
    }
}
