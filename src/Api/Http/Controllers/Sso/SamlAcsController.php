<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\OAuthServer\Support\SessionIdentifier;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * SAML Assertion Consumer Service. The IdP POSTs a signed `SAMLResponse` here,
 * keyed by the connection id in the route so multi-connection routing is
 * unambiguous. The endpoint is unauthenticated by design — the assertion's XML
 * signature is the authentication, verified by the {@see AssertionValidator}.
 *
 * On success it starts a session and returns its identifiers. A hosting app
 * wraps this (or the {@see FederationFlow}) to
 * turn the session into a cookie and redirect the browser.
 */
class SamlAcsController
{
    public function __construct(
        private readonly Connections $connections,
        private readonly AssertionValidator $validator,
        private readonly FederationFlow $flow,
    ) {}

    public function __invoke(Request $request, string $connection): JsonResponse
    {
        $model = $this->connections->byId($connection);

        if ($model === null || ! $model->isActive()) {
            return $this->error(404, 'Unknown or inactive connection.');
        }

        $samlResponse = $request->input('SAMLResponse');

        if (! is_string($samlResponse) || $samlResponse === '') {
            return $this->error(400, 'Missing SAMLResponse.');
        }

        try {
            $principal = $this->validator->validate($model, $samlResponse);
            $session = $this->flow->completeLogin($model, $principal);
        } catch (InvalidAssertion|ConnectionInactive $exception) {
            return $this->error(401, 'SSO assertion rejected.');
        } catch (AccountExistsForEmail $exception) {
            return $this->error(409, 'An account already exists for this email; link SSO from your account settings instead of signing in with it.');
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
