<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Contracts;

use Cbox\Id\SamlIdp\ValueObjects\SigningMaterial;

/**
 * Supplies the IdP's signing material: the unsealed RSA private key PEM (opened
 * in memory at signing time only) and the matching self-signed X.509 certificate
 * published in metadata. Both derive from the ONE platform signing key, so the
 * IdP presents the same identity as JWKS/OIDC — there is no second key store.
 */
interface IdpKeyMaterial
{
    /**
     * The active signing material (private key PEM + certificate PEM + kid). The
     * private key is opened via the Crypto kernel and never persisted in cleartext.
     */
    public function active(): SigningMaterial;
}
