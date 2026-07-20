<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\OidcClient;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
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
        private readonly OidcClient $client,
        private readonly AssertionValidator $validator,
        private readonly FederationFlow $flow,
    ) {}

    public function __invoke(Request $request, string $connection): JsonResponse
    {
        $model = $this->connections->byId($connection);

        if ($model === null || ! $model->isActive() || $model->type !== ConnectionType::Oidc) {
            return $this->error(404, 'Unknown or inactive OIDC connection.');
        }

        $stashed = $request->session()->pull('oidc.'.$model->id);
        $expectedState = is_array($stashed) && is_string($stashed['state'] ?? null) ? $stashed['state'] : null;
        $expectedNonce = is_array($stashed) && is_string($stashed['nonce'] ?? null) ? $stashed['nonce'] : null;

        $state = $request->string('state')->toString();
        $code = $request->string('code')->toString();

        // CSRF: the state must match the one we issued for this session.
        if ($expectedState === null || $code === '' || ! hash_equals($expectedState, $state)) {
            return $this->error(400, 'Invalid OIDC state or missing code.');
        }

        try {
            $idToken = $this->client->exchangeCode($model, $code, url('/sso/oidc/'.$model->id.'/callback'));
            $principal = $this->validator->validate($model, $idToken);

            // Replay defense: the id_token's nonce must be the one we sent.
            $nonce = $principal->raw['nonce'] ?? null;

            if ($expectedNonce === null || ! is_string($nonce) || ! hash_equals($expectedNonce, $nonce)) {
                return $this->error(401, 'OIDC nonce mismatch.');
            }

            $session = $this->flow->completeLogin($model, $principal);
        } catch (InvalidAssertion|ConnectionInactive) {
            return $this->error(401, 'OIDC login rejected.');
        } catch (AccountExistsForEmail) {
            return $this->error(409, 'An account already exists for this email; link SSO from your account settings instead.');
        }

        return new JsonResponse([
            'session_id' => $session->id,
            'user_id' => $session->user_id,
            'organization_id' => $session->organization_id,
        ]);
    }

    private function error(int $status, string $detail): JsonResponse
    {
        return new JsonResponse(['error' => $detail], $status);
    }
}
