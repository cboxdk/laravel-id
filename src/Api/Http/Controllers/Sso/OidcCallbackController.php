<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Contracts\OidcTokenExchange;
use Cbox\Id\Federation\Contracts\OidcUserInfo;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Support\FederationFlowStash;
use Cbox\Id\Federation\Support\FirstAuthorizationProfile;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\OAuthServer\Support\SessionIdentifier;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `GET /sso/oidc/{connection}/callback` — the OIDC redirect URI. Verifies `state`
 * against the session (CSRF), exchanges the code for an id_token, validates it
 * (signature/iss/aud via the {@see AssertionValidator}), checks the `nonce`
 * against the session (replay defense), then completes the login. Like the SAML
 * ACS it returns the session identifiers for the hosting app to turn into a cookie.
 */
class OidcCallbackController
{
    public function __construct(
        private readonly Connections $connections,
        private readonly OidcRelyingParty $client,
        private readonly AssertionValidator $validator,
        private readonly FederationFlow $flow,
        private readonly FederationFlowStash $stash,
        private readonly FirstAuthorizationProfile $firstAuthorization,
        private readonly ?OidcUserInfo $userInfo = null,
    ) {}

    public function __invoke(Request $request, string $connection): JsonResponse
    {
        $model = $this->connections->byId($connection);

        if ($model === null || ! $model->isActive() || $model->type !== ConnectionType::Oidc) {
            return $this->error(404, 'Unknown or inactive OIDC connection.');
        }

        // Pulled, not read: a replayed callback finds nothing stashed and fails closed.
        $expected = $this->stash->pull($request, $model->id);

        // `string()` reads the query OR the body, which is what makes a `form_post`
        // callback work at all — Apple POSTs these rather than putting them in the URL.
        $state = $request->string('state')->toString();
        $code = $request->string('code')->toString();

        // CSRF: the state must match the one we issued for this browser.
        if ($expected === null || $code === '' || ! $expected->matches($state)) {
            return $this->error(400, 'Invalid OIDC state or missing code.');
        }

        try {
            $redirectUri = url('/sso/oidc/'.$model->id.'/callback');

            // The access token is kept only when the bound relying party can hand it
            // over; a host's own OidcRelyingParty that cannot still signs people in, just
            // without what only UserInfo holds.
            if ($this->client instanceof OidcTokenExchange) {
                $tokens = $this->client->exchange($model, $code, $redirectUri);
                $idToken = $tokens->idToken;
                $accessToken = $tokens->accessToken;
            } else {
                $idToken = $this->client->exchangeCode($model, $code, $redirectUri);
                $accessToken = null;
            }

            $principal = $this->validator->validate($model, $idToken);

            // Replay defense: the id_token's nonce must be the one we sent.
            $nonce = $principal->raw['nonce'] ?? null;

            if (! is_string($nonce) || ! hash_equals($expected->nonce, $nonce)) {
                return $this->error(401, 'OIDC nonce mismatch.');
            }

            // The name a provider sends ONCE, outside the assertion — Apple, and only
            // Apple, on the first authorization. Merged before provisioning, because
            // provisioning is what creates the account and there is no second chance.
            $principal = $this->firstAuthorization->merge($model, $request, $principal);

            // The address a provider keeps behind UserInfo rather than in the token —
            // Intuit. AFTER the nonce check, so only a proven subject is completed.
            $principal = ($this->userInfo ?? app(OidcUserInfo::class))->complete($model, $principal, $accessToken);

            $session = $this->flow->completeLogin($model, $principal);
        } catch (InvalidAssertion|ConnectionInactive) {
            return $this->error(401, 'OIDC login rejected.');
        } catch (AccountExistsForEmail) {
            return $this->error(409, 'An account already exists for this email; link SSO from your account settings instead.');
        }

        // `sid`, NOT the row key. `auth_sessions.id` is a ULID: it dates the session to
        // the millisecond and is the handle the host's own session screens and
        // `SessionManager::revoke()` are addressed by, so it never leaves the server.
        // The value here is the same opaque digest the ID Token's `sid` and the
        // back-channel logout token carry ({@see SessionIdentifier}), so one session has
        // one public name everywhere. A host that needs the session itself calls
        // `FederationFlow::completeLogin()` from its own controller and keeps the model.
        return new JsonResponse([
            'sid' => SessionIdentifier::sid($session->id),
            'user_id' => $session->user_id,
            'organization_id' => $session->organization_id,
        ]);
    }

    private function error(int $status, string $detail): JsonResponse
    {
        return new JsonResponse(['error' => $detail], $status);
    }
}
