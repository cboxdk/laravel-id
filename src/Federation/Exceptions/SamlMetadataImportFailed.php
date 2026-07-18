<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use RuntimeException;

/**
 * The pasted or fetched SAML metadata could not be turned into a usable connection
 * prefill — malformed XML, no IDPSSODescriptor, or a descriptor missing the entity
 * id / SSO URL / signing certificate the assertion validator requires.
 */
final class SamlMetadataImportFailed extends RuntimeException
{
    public static function make(string $reason): self
    {
        return new self('Could not import SAML metadata: '.$reason);
    }
}
