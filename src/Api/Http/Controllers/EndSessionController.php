<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\OAuthServer\Contracts\EndSession;
use Cbox\Id\OAuthServer\ValueObjects\EndSessionRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * `GET|POST /oauth/logout` — the OIDC `end_session_endpoint` (OpenID Connect
 * RP-Initiated Logout 1.0). It terminates the End-User's sessions at this OP and,
 * when the RP supplied a `post_logout_redirect_uri` that the resolver validated
 * against the client's allow-list, sends the browser back there (carrying `state`).
 *
 * Session teardown is the controller's job; the open-redirect guard lives in the
 * {@see EndSession} resolver. The endpoint only ever REVOKES a session and never
 * mints one, so an unauthenticated or forged request cannot gain anything.
 */
class EndSessionController
{
    public function __construct(
        private readonly EndSession $endSession,
        private readonly SessionManager $sessions,
    ) {}

    public function __invoke(Request $request): RedirectResponse|Response
    {
        $result = $this->endSession->resolve(new EndSessionRequest(
            idTokenHint: $this->param($request, 'id_token_hint'),
            clientId: $this->param($request, 'client_id'),
            postLogoutRedirectUri: $this->param($request, 'post_logout_redirect_uri'),
            state: $this->param($request, 'state'),
        ));

        $this->terminate($request);

        if ($result->hasRedirect()) {
            return new RedirectResponse((string) $result->redirectTo);
        }

        return new Response('You are signed out.', 200, ['Content-Type' => 'text/plain; charset=UTF-8']);
    }

    /**
     * Revoke every session for the currently-authenticated subject and clear this
     * browser's session, so a subsequent SSO handshake requires re-authentication.
     */
    private function terminate(Request $request): void
    {
        $subjectId = auth()->id();

        if (is_string($subjectId) || is_int($subjectId)) {
            $this->sessions->revokeAllForUser((string) $subjectId);
        }

        auth()->guard()->logout();

        if ($request->hasSession()) {
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }
    }

    private function param(Request $request, string $key): ?string
    {
        $value = $request->input($key);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
