<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use Cbox\Id\SamlIdp\Enums\SamlBinding;

/**
 * The result of processing an inbound `LogoutRequest`: the `NameID` the SP asked
 * to log out (verified to come from a signed request by a registered SP), and the
 * signed `LogoutResponse` addressed back to that SP's SLO endpoint — carried by
 * the SAME binding the request arrived on.
 *
 * The controller revokes the session and then delivers exactly one of the two:
 * a 302 to `redirectUrl` (HTTP-Redirect), or `postForm` as an HTML body
 * (HTTP-POST). `binding` says which; the other field is empty.
 */
readonly class SamlLogoutOutcome
{
    private function __construct(
        /**
         * WHO asked. Carried because a NameID alone does not identify anyone safely: it
         * is scoped to the service provider that received it, and for the default
         * emailAddress format it is simply the person's email address. Resolving one
         * without knowing which SP presented it let any registered SP log out any user.
         */
        public string $spEntityId,
        public string $nameId,
        public SamlBinding $binding,
        public string $redirectUrl,
        public string $postForm,

        /**
         * The POST payload together with the content policy that permits it.
         *
         * `postForm` is the same HTML and stays for callers that only need the body.
         * A host with any real Content-Security-Policy needs this one instead: a
         * self-submitting cross-origin form is, to a browser, exactly the shape
         * `form-action` and the inline-script ban exist to stop.
         */
        public ?SamlPostBinding $postBinding = null,
    ) {}

    /** A `LogoutResponse` delivered by the HTTP-Redirect binding (detached signature). */
    public static function redirect(string $spEntityId, string $nameId, string $redirectUrl): self
    {
        return new self($spEntityId, $nameId, SamlBinding::Redirect, $redirectUrl, '');
    }

    /** A `LogoutResponse` delivered by the HTTP-POST binding (enveloped XML-DSig). */
    public static function post(string $spEntityId, string $nameId, SamlPostBinding $binding): self
    {
        return new self($spEntityId, $nameId, SamlBinding::Post, '', $binding->html, $binding);
    }
}
