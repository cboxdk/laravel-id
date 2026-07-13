<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Saml\SamlLogout;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * SAML 2.0 Single Logout endpoint. The IdP sends a signed `LogoutRequest` here
 * (or a `LogoutResponse` closing an SP-initiated logout); {@see SamlLogout}
 * verifies the signature, revokes the subject's sessions, and returns the
 * `LogoutResponse` redirect back to the IdP. Unauthenticated by design — the
 * message signature is the authentication.
 */
final class SamlLogoutController
{
    public function __construct(
        private readonly Connections $connections,
        private readonly SamlLogout $logout,
    ) {}

    public function __invoke(Request $request, string $connection): RedirectResponse|Response
    {
        $model = $this->connections->byId($connection);

        if ($model === null || $model->type !== ConnectionType::Saml) {
            return new Response('Unknown SAML connection.', 404);
        }

        // Collect the SLO parameters from GET (redirect binding) or POST.
        $params = [];
        foreach (['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature'] as $key) {
            $value = $request->input($key);
            if (is_string($value) && $value !== '') {
                $params[$key] = $value;
            }
        }

        if (! isset($params['SAMLRequest']) && ! isset($params['SAMLResponse'])) {
            return new Response('Missing SAMLRequest or SAMLResponse.', 400);
        }

        $result = $this->logout->handle($model, $params);

        if (! $result->valid) {
            return new Response('SLO rejected.', 400);
        }

        // A LogoutRequest yields a LogoutResponse redirect back to the IdP; a
        // LogoutResponse (closing our own logout) has nowhere further to go.
        if ($result->redirectUrl !== null) {
            return new RedirectResponse($result->redirectUrl);
        }

        return new Response('', 204);
    }
}
