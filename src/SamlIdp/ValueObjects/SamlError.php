<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use Cbox\Id\SamlIdp\Enums\SamlStatusCode;

/**
 * Everything needed to answer a refused `AuthnRequest` with a real SAML
 * `Response` carrying a failure `StatusCode`, instead of dropping the user on an
 * unbranded HTTP error page the SP never hears about.
 *
 * This object only ever exists for a request that ALREADY cleared the trust
 * gates — the issuer is a registered, active SP, its ACS matched the
 * registration, and any required signature verified. That is deliberate: the
 * response is delivered to `acsUrl`, and an error response for an unknown SP, a
 * mismatched ACS, or an unverified signature would be exactly the open-redirect /
 * unauthenticated-POST sink the ACS pinning exists to prevent. Those stay plain
 * HTTP refusals.
 */
readonly class SamlError
{
    public function __construct(
        public string $spEntityId,
        public string $acsUrl,
        public SamlStatusCode $status,
        public ?SamlStatusCode $subStatus = null,
        public ?string $inResponseTo = null,
        public ?string $relayState = null,
        public ?string $message = null,
    ) {}
}
