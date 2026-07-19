<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use DOMDocument;

/**
 * Builds an unsigned SAML 2.0 `<samlp:LogoutResponse>` document. Under the
 * HTTP-Redirect binding the message integrity comes from the DETACHED query
 * signature ({@see RedirectBindingResponseSigner}), not an embedded XML signature —
 * so this only assembles the well-formed response element (a Success status closing
 * the SP's `LogoutRequest`, echoing its ID via `InResponseTo`, addressed to the SP's
 * SLO endpoint via `Destination`). Kept tiny and deterministic; the crypto lives
 * entirely in the signer.
 */
final class LogoutResponseBuilder
{
    private const NS_PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const NS_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    public function build(string $idpEntityId, string $destination, string $inResponseTo): string
    {
        $document = new DOMDocument('1.0', 'UTF-8');

        $response = $document->createElementNS(self::NS_PROTOCOL, 'samlp:LogoutResponse');
        $document->appendChild($response);
        $response->setAttribute('ID', '_'.bin2hex(random_bytes(16)));
        $response->setAttribute('Version', '2.0');
        $response->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z'));
        $response->setAttribute('Destination', $destination);
        $response->setAttribute('InResponseTo', $inResponseTo);

        $issuer = $document->createElementNS(self::NS_ASSERTION, 'saml:Issuer');
        $issuer->appendChild($document->createTextNode($idpEntityId));
        $response->appendChild($issuer);

        $status = $document->createElementNS(self::NS_PROTOCOL, 'samlp:Status');
        $statusCode = $document->createElementNS(self::NS_PROTOCOL, 'samlp:StatusCode');
        $statusCode->setAttribute('Value', self::STATUS_SUCCESS);
        $status->appendChild($statusCode);
        $response->appendChild($status);

        return (string) $document->saveXML();
    }
}
