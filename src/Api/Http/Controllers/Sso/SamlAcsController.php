<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
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
final class SamlAcsController
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
