<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SignedInSubject;
use Cbox\Id\OAuthServer\Contracts\EndSession;
use Cbox\Id\OAuthServer\ValueObjects\EndSessionRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;

/**
 * `GET|POST /oauth/logout` — the OIDC `end_session_endpoint` (OpenID Connect
 * RP-Initiated Logout 1.0). It terminates the End-User's sessions at this OP and,
 * when the RP supplied a `post_logout_redirect_uri` that the resolver validated
 * against the client's allow-list, sends the browser back there (carrying `state`).
 *
 * Session teardown is the controller's job; the open-redirect guard lives in the
 * {@see EndSession} resolver. The endpoint only ever REVOKES a session and never mints
 * one — but "revokes" is not automatically harmless, and how much it revokes depends on
 * whether the request can be believed. See {@see terminate()}.
 */
class EndSessionController
{
    public function __construct(
        private readonly EndSession $endSession,
        private readonly SessionManager $sessions,
        private readonly SignedInSubject $signedIn,
    ) {}

    public function __invoke(Request $request): RedirectResponse|Response
    {
        $endSessionRequest = new EndSessionRequest(
            idTokenHint: $this->param($request, 'id_token_hint'),
            clientId: $this->param($request, 'client_id'),
            postLogoutRedirectUri: $this->param($request, 'post_logout_redirect_uri'),
            state: $this->param($request, 'state'),
        );

        $result = $this->endSession->resolve($endSessionRequest);

        $this->terminate($request, $result->subject);

        if ($result->hasRedirect()) {
            return new RedirectResponse((string) $result->redirectTo);
        }

        return new Response(
            'You are signed out.'.$this->droppedRedirectNotice($endSessionRequest),
            200,
            ['Content-Type' => 'text/plain; charset=UTF-8'],
        );
    }

    /**
     * The RP asked to be redirected and we refused. That is the correct outcome for
     * an unidentifiable or unregistered URI, but silence here costs integrators hours
     * — so say why. The reason is always logged; the text is appended to the response
     * only under `app.debug`, since it echoes back what the caller sent and names our
     * allow-list decision (both fine locally, neither belongs on a production page).
     */
    private function droppedRedirectNotice(EndSessionRequest $request): string
    {
        if ($request->postLogoutRedirectUri === null) {
            return '';
        }

        $identified = $request->clientId !== null || $request->idTokenHint !== null;

        $reason = $identified
            ? 'the URI is not on that client\'s registered post_logout_redirect_uris (matching is exact — scheme, host, path and trailing slash all count)'
            : 'the request identified no client: send `client_id`, or an `id_token_hint` we can verify, so we know whose allow-list to check';

        Log::info('RP-initiated logout dropped post_logout_redirect_uri', [
            'reason' => $identified ? 'uri_not_allowed' : 'client_unidentified',
            'client_id' => $request->clientId,
            'had_id_token_hint' => $request->idTokenHint !== null,
            'post_logout_redirect_uri' => $request->postLogoutRedirectUri,
        ]);

        if (config('app.debug') !== true) {
            return '';
        }

        return "\n\npost_logout_redirect_uri was ignored because ".$reason.".\n"
            ."Requested: {$request->postLogoutRedirectUri}\n"
            .'Register it on the client (Applications → Sign-out URIs) and have the app send `client_id` on the logout request.';
    }

    /**
     * End the session, and decide HOW MUCH of it to end from whether the request can be
     * believed.
     *
     * This endpoint is unauthenticated by design — RP-Initiated Logout is reached by a
     * browser redirect from a relying party — and it answers GET. So the global revoke
     * can only be driven by a request that PROVES which End-User it concerns, which is
     * exactly what `id_token_hint` is for: `$verifiedSubject` is the `sub` of a hint this
     * server verified against its own keys, or null when none was supplied.
     *
     * Without that proof, only this browser is signed out. With it — and only when the
     * hint names the person actually holding this browser — every session that person
     * holds is revoked, which is what a relying party means by global sign-out.
     *
     * THE DISTINCTION IS THE WHOLE CONTROL. When the subject came from the host's session
     * alone, `<img src="https://id.example.com/oauth/logout">` on any page in the world
     * signed the viewer out of every device they owned. The endpoint mints nothing, so
     * that was never an escalation — it was a denial of service against every user of
     * every deployment, delivered by an image tag.
     */
    private function terminate(Request $request, ?string $verifiedSubject): void
    {
        // THROUGH THE CONTRACT, not `auth()->id()`. A host that keeps its own session
        // answers null to the guard forever, so this revocation silently never ran while
        // logout still cleared the browser and returned 200 — a relying party asking for
        // global sign-out got success and no global sign-out.
        $subjectId = $this->signedIn->id();

        if ($subjectId !== null && $verifiedSubject !== null && hash_equals($subjectId, $verifiedSubject)) {
            $this->sessions->revokeAllForUser($subjectId);
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
