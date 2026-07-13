<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Saml\SamlSettings;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use OneLogin\Saml2\AuthnRequest;
use Throwable;

/**
 * SP-initiated SAML SSO. The browser hits this endpoint; we build a SAML 2.0
 * `AuthnRequest` and redirect (HTTP-Redirect binding) to the IdP's SSO service.
 * The IdP authenticates the user and POSTs a `SAMLResponse` back to the ACS.
 *
 * The AuthnRequest id is stashed in the session so the ACS can enforce
 * `InResponseTo` (defeating unsolicited-response injection); `RelayState`
 * carries the post-login destination back through the round-trip.
 */
final class SamlLoginController
{
    /** Session key holding the last AuthnRequest id, for InResponseTo checks. */
    public const REQUEST_ID_KEY = 'cbox.saml_authn_request_id';

    public function __construct(private readonly Connections $connections) {}

    public function __invoke(Request $request, string $connection): RedirectResponse|Response
    {
        $model = $this->connections->byId($connection);

        if ($model === null || $model->type !== ConnectionType::Saml || ! $model->isActive()) {
            return new Response('Unknown or inactive SAML connection.', 404);
        }

        $config = $this->connections->config($model);
        $ssoUrl = $config['idp_sso_url'] ?? null;

        if (! is_string($ssoUrl) || $ssoUrl === '') {
            return new Response('SAML connection is not fully configured.', 422);
        }

        try {
            $authn = new AuthnRequest(SamlSettings::for($config));
        } catch (Throwable) {
            return new Response('SAML connection is not fully configured.', 422);
        }

        // Remember the request id so the ACS can reject unsolicited responses.
        $request->session()->put(self::REQUEST_ID_KEY, $authn->getId());

        $params = ['SAMLRequest' => $authn->getRequest()];

        $relayState = $request->query('relay');
        if (is_string($relayState) && $relayState !== '') {
            $params['RelayState'] = $relayState;
        }

        $separator = str_contains($ssoUrl, '?') ? '&' : '?';

        return new RedirectResponse($ssoUrl.$separator.http_build_query($params));
    }
}
