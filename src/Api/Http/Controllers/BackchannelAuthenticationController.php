<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Exceptions\UnknownUserHint;
use Cbox\Id\OAuthServer\Support\GrantPolicy;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/backchannel_authentication` — the CIBA backchannel authentication
 * endpoint (OpenID Connect CIBA Core §7). A client (typically an autonomous / AI
 * agent) starts a decoupled authentication here by naming the user with
 * `login_hint`; the user approves out-of-band, and the client then polls the token
 * endpoint with the returned `auth_req_id`.
 */
class BackchannelAuthenticationController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly BackchannelAuthentication $ciba,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        // Client-authenticated like the token endpoint, and CONFIDENTIALLY so.
        //
        // authenticate() lets a public client through on client_id alone, which is safe
        // where a front channel and PKCE bind the flow to the browser that started it.
        // CIBA has neither: there is no redirect, no code_verifier, and the only human
        // check is the approval prompt this endpoint puts on someone's phone. So a public
        // client_id — which is not a secret and travels in every app binary — was enough
        // to spray prompts at arbitrary users via login_hint, and a person who has
        // dismissed thirty of them approves the thirty-first.
        $client = $this->clientAuth->authenticateConfidential($request);

        if ($client === null) {
            return new JsonResponse(['error' => 'invalid_client'], 401);
        }

        // Enforce the registered grant at INITIATION, not only at redemption: otherwise a
        // client that can never complete this flow still creates its state and puts a
        // prompt in front of a user.
        if (! GrantPolicy::allows($client, 'urn:openid:params:grant-type:ciba')) {
            return new JsonResponse(['error' => 'unauthorized_client'], 400);
        }

        $loginHint = trim($request->string('login_hint')->toString());

        // CIBA Core §7.1: exactly one hint is required to identify the user. We
        // support login_hint; a request with none cannot be fulfilled.
        if ($loginHint === '') {
            return new JsonResponse(['error' => 'invalid_request'], 400);
        }

        $scope = $request->string('scope')->toString();
        $scopes = $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));

        $bindingMessage = $request->string('binding_message')->toString();
        $requestedExpiry = $request->has('requested_expiry') ? $request->integer('requested_expiry') : null;

        // OIDC CIBA Core §7.1: the optional `nonce` binds the eventual id_token to
        // this backchannel request so the client can detect replay. CIBA persists it
        // and the id_token path echoes it — so thread it through here rather than
        // dropping it. A blank/whitespace-only value is treated as absent.
        $nonce = trim($request->string('nonce')->toString());

        try {
            $result = $this->ciba->request(
                $client,
                $scopes,
                $loginHint,
                $bindingMessage !== '' ? $bindingMessage : null,
                $nonce !== '' ? $nonce : null,
                $requestedExpiry,
            );
        } catch (UnknownUserHint) {
            return new JsonResponse(['error' => 'unknown_user_id'], 400);
        }

        // Only the client-facing fields are serialized — never the internal request
        // id the host uses to approve.
        return new JsonResponse([
            'auth_req_id' => $result->authReqId,
            'expires_in' => $result->expiresIn,
            'interval' => $result->interval,
        ]);
    }
}
