<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Identity\Contracts\SessionManager;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * The IdP SingleLogoutService endpoint. Scope is deliberately honest and narrow:
 * it terminates the subject's LOCAL platform sessions (IdP-side logout) so a new
 * SSO handshake requires re-authentication. It does NOT yet fan out signed
 * LogoutRequests to every federated SP, nor emit a signed LogoutResponse — those
 * are documented as not-yet-implemented (see docs/core-concepts/saml-idp.md).
 *
 * The endpoint only ever REVOKES; it never creates or elevates a session, so an
 * unauthenticated or unsigned inbound request cannot be abused for privilege gain.
 */
final class SamlIdpLogoutController
{
    public function __construct(private readonly SessionManager $sessions) {}

    public function __invoke(Request $request): Response
    {
        $subjectId = auth()->id();

        if (is_string($subjectId) || is_int($subjectId)) {
            $this->sessions->revokeAllForUser((string) $subjectId);
        }

        return new Response('Signed out.', 200, ['Content-Type' => 'text/plain; charset=UTF-8']);
    }
}
