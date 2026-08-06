<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\ValueObjects;

use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;

/**
 * A parsed and fully-validated SAML 2.0 `AuthnRequest`.
 *
 * By the time this object exists, the request has already cleared every gate in
 * {@see SamlIdentityProvider::parseAuthnRequest()}: the
 * issuer is a registered, active SP; any required signature verified; and the
 * request-supplied ACS (if present) matched the registered ACS exactly.
 *
 * `acsUrl` is the REGISTERED ACS for the SP — never a value copied from the
 * request — so a response is always delivered to the trusted, pre-agreed
 * location. `serviceProviderId` re-resolves the SP for issuance (deny-by-default
 * a second time), and `spEntityId` is the audience the assertion is restricted to.
 */
readonly class AuthnRequest
{
    public function __construct(
        public string $id,
        public string $spEntityId,
        public string $serviceProviderId,
        public string $acsUrl,
        public ?string $requestedNameIdFormat = null,
        public ?string $relayState = null,
    ) {}
}
