<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\SamlIdp\Contracts\SamlSingleLogout;
use Cbox\Id\SamlIdp\Exceptions\InvalidLogoutRequest;
use Cbox\Id\SamlIdp\ValueObjects\LogoutMessage;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * The IdP SingleLogoutService endpoint (SAML 2.0 Single Logout, HTTP-Redirect
 * binding). Two shapes arrive here:
 *
 *  - **SP-initiated SLO** — a signed `LogoutRequest` (`SAMLRequest`). The
 *    {@see SamlSingleLogout} service verifies its signature against the SP's
 *    registered certificate, and we tear down the local session and 302 a signed
 *    `LogoutResponse` back to the SP's SLO endpoint so the SP completes its logout.
 *  - **Plain logout** — no `SAMLRequest`. We simply revoke the subject's local
 *    sessions so the next SSO handshake re-authenticates.
 *
 * The endpoint only ever REVOKES a session; it never mints or elevates one, so an
 * unauthenticated or unsigned request can gain nothing. An invalid `LogoutRequest`
 * (unknown SP, bad signature, no SLO endpoint) is refused with 400 — never processed
 * on trust.
 */
class SamlIdpLogoutController
{
    public function __construct(
        private readonly SessionManager $sessions,
        private readonly SamlSingleLogout $singleLogout,
    ) {}

    public function __invoke(Request $request): RedirectResponse|Response
    {
        $samlRequest = $this->param($request, 'SAMLRequest');

        // A plain logout with no SAML message: revoke and done.
        if ($samlRequest === null) {
            $this->terminate();

            return new Response('Signed out.', 200, ['Content-Type' => 'text/plain; charset=UTF-8']);
        }

        // SP-initiated SLO: VALIDATE the (signed) LogoutRequest BEFORE touching the
        // session. Terminating first would let a bogus SLO URL force-log-out whoever
        // is signed in (a forced-logout via a cross-site GET) before the 400.
        try {
            $outcome = $this->singleLogout->process(new LogoutMessage(
                samlRequest: $samlRequest,
                relayState: $this->param($request, 'RelayState'),
                signature: $this->param($request, 'Signature'),
                sigAlg: $this->param($request, 'SigAlg'),
            ));
        } catch (InvalidLogoutRequest) {
            return new Response('SLO rejected.', 400, ['Content-Type' => 'text/plain; charset=UTF-8']);
        }

        $this->terminate();

        return new RedirectResponse($outcome->redirectUrl);
    }

    /** Revoke every session for the currently-authenticated subject. */
    private function terminate(): void
    {
        $subjectId = auth()->id();

        if (is_string($subjectId) || is_int($subjectId)) {
            $this->sessions->revokeAllForUser((string) $subjectId);
        }
    }

    private function param(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
