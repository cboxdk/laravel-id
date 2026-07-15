<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Exceptions;

use RuntimeException;

/**
 * Thrown when the IdP cannot assemble its signing material — the active platform
 * key is not RSA (SAML signing here is pinned to RSA-SHA256), or the self-signed
 * certificate could not be generated. The IdP refuses to emit an unsigned or
 * weak-algorithm assertion rather than degrade.
 */
final class SigningMaterialUnavailable extends RuntimeException
{
    public static function notRsa(string $alg): self
    {
        return new self('SAML IdP signing requires an RSA key; active key algorithm is ['.$alg.']');
    }

    public static function certificateFailed(string $detail): self
    {
        return new self('could not generate the IdP signing certificate: '.$detail);
    }
}
