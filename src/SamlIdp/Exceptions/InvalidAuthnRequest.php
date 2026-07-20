<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use RuntimeException;

/**
 * Thrown when an inbound SAML `AuthnRequest` is rejected: malformed XML (or a
 * DOCTYPE/XXE payload), a missing issuer or id, an AssertionConsumerServiceURL
 * that does not match the registered ACS, a required-but-absent signature, an
 * unknown signature algorithm, or a signature that fails to verify. Never carries
 * the raw request payload.
 */
class InvalidAuthnRequest extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('invalid AuthnRequest: '.$reason);
    }
}
