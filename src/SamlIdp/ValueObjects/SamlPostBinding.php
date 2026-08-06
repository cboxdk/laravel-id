<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use Illuminate\Http\Response;

/**
 * A SAML HTTP-POST payload together with the one content policy that lets it work.
 *
 * The POST binding (SAML bindings §3.5) is a self-submitting HTML form aimed at another
 * origin — the service provider's ACS. That is indistinguishable, to a browser, from the
 * cross-site form post that `form-action` exists to stop, and the auto-submit is
 * indistinguishable from injected script. A host with an ordinary hardened policy
 * therefore breaks its own federation: with `form-action 'self'` the POST is refused, and
 * with a `script-src` that has no `'unsafe-inline'` the submit never fires. The user
 * lands on a blank page and the SP is never told anything went wrong.
 *
 * The trap is the obvious remedy — loosening the global policy — which trades every
 * page's clickjacking and form-hijack protection for one endpoint's needs. So the policy
 * travels WITH the response instead: `default-src 'none'` and a nonce for the single
 * submit script, with `form-action` naming only the ACS this particular assertion is
 * addressed to. That ACS comes from the SP's registration, never from the request, so the
 * allowance cannot be widened by anything an attacker sends.
 *
 * Carried as a value object rather than assembled in the controller because there are
 * four emission sites across two repositories, and the last time one of them was
 * reimplemented by hand it silently dropped a feature nobody noticed for weeks.
 */
readonly class SamlPostBinding
{
    public function __construct(
        public string $html,
        public string $contentSecurityPolicy,
    ) {}

    /**
     * The response to return from a controller, policy attached.
     */
    public function toResponse(int $status = 200): Response
    {
        return new Response($this->html, $status, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Content-Security-Policy' => $this->contentSecurityPolicy,
            // The page exists for the fraction of a second before it submits itself.
            // Anything that stores it stores a signed assertion.
            'Cache-Control' => 'no-store',
        ]);
    }
}
