<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use RuntimeException;

/**
 * Thrown when an AuthnRequest names a service provider that is not registered in
 * this environment, or one whose status is not active. The IdP never mints an
 * assertion for an SP it does not know — deny-by-default.
 */
final class UnknownServiceProvider extends RuntimeException
{
    public static function forEntityId(string $entityId): self
    {
        return new self('no active SAML service provider registered for issuer ['.$entityId.']');
    }
}
