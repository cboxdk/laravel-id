<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\SamlAuthRequest;
use Cbox\Id\Federation\Saml\SamlSettings;
use Cbox\Id\Federation\Support\BrowserStartUrl;
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
 * The AuthnRequest id is persisted in `saml_auth_requests` so the ACS can
 * enforce `InResponseTo` (defeating unsolicited-response injection). We can't
 * rely on the session for this: the ACS is a cross-site POST from the IdP where
 * the SameSite=Lax session cookie is absent. `RelayState` carries the post-login
 * destination back through the round-trip.
 */
class SamlLoginController
{
    /** Session key mirroring the last AuthnRequest id (best-effort UX only). */
    public const REQUEST_ID_KEY = 'cbox.saml_authn_request_id';

    /** Outstanding SP-initiated AuthnRequests live this long before expiring. */
    private const REQUEST_TTL_MINUTES = 10;

    public function __construct(private readonly Connections $connections) {}

    public function __invoke(Request $request, string $connection): RedirectResponse|Response
    {
        $model = $this->connections->byId($connection);

        if ($model === null || $model->type !== ConnectionType::Saml || ! $model->isActive()) {
            return new Response('Unknown or inactive SAML connection.', 404);
        }

        try {
            // Parsing the config asserts every required field — including the SSO URL
            // used below — so the separate pre-check this replaces is now redundant.
            $config = $this->connections->samlConfig($model);

            // Checked here rather than only at write time, so a connection already in the
            // database — configured before this guard existed, or through a future write
            // path — cannot be used as an open redirect wearing this platform's domain.
            // Inside this block, and before the request row below: a connection we will
            // not redirect to should not leave an authn request behind either.
            $ssoUrl = BrowserStartUrl::assert($config->idpSsoUrl, 'idp_sso_url');
            $authn = new AuthnRequest(SamlSettings::for($config));
        } catch (Throwable) {
            return new Response('SAML connection is not fully configured.', 422);
        }

        // Record the request id (connection-scoped, short-lived) so the ACS can
        // reject responses whose InResponseTo we never issued. The store — not the
        // session — is authoritative: the ACS POST carries no session cookie.
        SamlAuthRequest::query()->create([
            'request_id' => $authn->getId(),
            'connection_id' => $model->id,
            'expires_at' => now()->addMinutes(self::REQUEST_TTL_MINUTES),
        ]);
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
