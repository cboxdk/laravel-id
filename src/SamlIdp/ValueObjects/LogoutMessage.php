<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

/**
 * The raw inbound HTTP-Redirect-binding parameters of a SAML Single Logout message,
 * exactly as received on the query string (still base64/deflated, already
 * URL-decoded by the framework). Passing them as one typed object keeps the
 * controller from threading four loose strings through the service boundary.
 */
readonly class LogoutMessage
{
    public function __construct(
        public string $samlRequest,
        public ?string $relayState = null,
        public ?string $signature = null,
        public ?string $sigAlg = null,
    ) {}
}
