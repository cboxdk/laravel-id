<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

/**
 * Signs an outbound SAML message under the HTTP-Redirect binding (SAML bindings
 * §3.4.4.1): the message is DEFLATE-compressed and base64-encoded, then the
 * URL-encoded `SAMLResponse=…&RelayState=…&SigAlg=…` octet string is signed with
 * the IdP private key and the base64 `Signature` appended. The octet-string
 * construction mirrors, byte for byte, what a conformant verifier (onelogin's
 * {@see Utils::validateBinarySign()}, which our inbound
 * {@see RedirectBindingSignature} uses) reconstructs — otherwise a real SP would
 * reject the signature.
 *
 * The RSA signing itself is delegated to xmlseclibs (openssl under the hood), with
 * the algorithm PINNED to RSA-SHA256 — never SHA-1, never inferred.
 */
final class RedirectBindingResponseSigner
{
    /**
     * @param  string  $type  the query parameter name — `SAMLResponse` or `SAMLRequest`
     * @return string the fully-formed redirect URL (destination + signed query)
     */
    public function sign(
        string $destination,
        string $xml,
        ?string $relayState,
        string $privateKeyPem,
        string $type = 'SAMLResponse',
    ): string {
        // Redirect binding: raw DEFLATE (no zlib header), then base64.
        $encoded = base64_encode((string) gzdeflate($xml));
        $sigAlg = XMLSecurityKey::RSA_SHA256;

        // The signed octet string: values URL-encoded, in the fixed order the spec
        // (and every conformant verifier) reconstructs — message, RelayState?, SigAlg.
        $signedQuery = $type.'='.urlencode($encoded);
        if ($relayState !== null && $relayState !== '') {
            $signedQuery .= '&RelayState='.urlencode($relayState);
        }
        $signedQuery .= '&SigAlg='.urlencode($sigAlg);

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
        $key->loadKey($privateKeyPem, false);

        $signature = $key->signData($signedQuery);

        if (! is_string($signature)) {
            throw new RuntimeException('failed to sign the SAML redirect binding');
        }

        $query = $signedQuery.'&Signature='.urlencode(base64_encode($signature));

        return $destination.(str_contains($destination, '?') ? '&' : '?').$query;
    }
}
