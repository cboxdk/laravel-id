<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;
use Illuminate\Http\Response;
use Throwable;

/**
 * Publishes this platform's SAML 2.0 Identity Provider metadata: EntityID, the
 * SingleSignOnService endpoints, the SingleLogoutService endpoint and the signing
 * X.509 certificate. An SP administrator imports this URL during federation setup.
 * Public by design — metadata carries no secrets (only the public certificate).
 */
final class SamlIdpMetadataController
{
    public function __construct(private readonly SamlIdentityProvider $idp) {}

    public function __invoke(): Response
    {
        try {
            $xml = $this->idp->metadata();
        } catch (Throwable) {
            return new Response('SAML IdP is not fully configured.', 503);
        }

        return new Response($xml, 200, [
            'Content-Type' => 'application/samlmetadata+xml',
            'Content-Disposition' => 'attachment; filename="cbox-id-idp-metadata.xml"',
        ]);
    }
}
