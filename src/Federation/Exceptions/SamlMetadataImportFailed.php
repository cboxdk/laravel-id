<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Exceptions;

use Cbox\Id\Kernel\Presentation\Concerns\CarriesSourceMessage;
use Cbox\Id\Kernel\Presentation\Contracts\HasSourceMessage;
use RuntimeException;

/**
 * The pasted or fetched SAML metadata could not be turned into a usable connection
 * prefill — malformed XML, no IDPSSODescriptor, or a descriptor missing the entity
 * id / SSO URL / signing certificate the assertion validator requires.
 */
class SamlMetadataImportFailed extends RuntimeException implements HasSourceMessage
{
    use CarriesSourceMessage;

    public static function make(string $reason): self
    {
        return new self('Could not import SAML metadata: '.$reason);
    }
}
