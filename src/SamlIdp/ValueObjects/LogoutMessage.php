<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use Cbox\Id\SamlIdp\Enums\SamlBinding;

/**
 * The raw inbound parameters of a SAML Single Logout message, exactly as received
 * (still base64/deflated, already URL-decoded by the framework). Passing them as
 * one typed object keeps the controller from threading loose strings through the
 * service boundary.
 *
 * `binding` is how the message ARRIVED, and it decides everything downstream:
 * HTTP-Redirect carries the detached `Signature`/`SigAlg` query parameters and is
 * answered with a signed redirect; HTTP-POST carries an enveloped XML-DSig inside
 * the `LogoutRequest` itself and is answered with a self-submitting form. Okta and
 * ADFS prefer POST, so treating every message as redirect-bound rejected them all.
 */
readonly class LogoutMessage
{
    public function __construct(
        public string $samlRequest,
        public ?string $relayState = null,
        public ?string $signature = null,
        public ?string $sigAlg = null,
        public SamlBinding $binding = SamlBinding::Redirect,
    ) {}
}
