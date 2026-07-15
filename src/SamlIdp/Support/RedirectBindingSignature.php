<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Support;

use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Throwable;

/**
 * Verifies the detached signature on an HTTP-Redirect-binding `AuthnRequest`
 * (SAML bindings §3.4.4.1): the SP signs the URL-encoded
 * `SAMLRequest=…&RelayState=…&SigAlg=…` octet string, and we verify it against the
 * SP's registered certificate. The RSA verification itself is delegated to
 * onelogin's {@see SamlUtils::validateBinarySign()} (which uses xmlseclibs) — we
 * only enforce policy: the algorithm is pinned to RSA-SHA256, so a SHA-1 or
 * unknown `SigAlg` is refused before any verification is attempted.
 */
final class RedirectBindingSignature
{
    /**
     * @throws InvalidAuthnRequest unknown algorithm, missing certificate, or a
     *                             signature that does not verify
     */
    public function verify(
        string $samlRequest,
        ?string $relayState,
        ?string $signature,
        ?string $sigAlg,
        ?string $certificatePem,
    ): void {
        if ($signature === null || $signature === '') {
            throw InvalidAuthnRequest::make('a signed AuthnRequest is required but no Signature was supplied');
        }

        // Algorithm pin: only RSA-SHA256 is accepted. SHA-1 (the historical SAML
        // default) and every other SigAlg is refused — never inferred, never
        // defaulted (onelogin would otherwise default a missing SigAlg to SHA-1).
        if ($sigAlg !== XMLSecurityKey::RSA_SHA256) {
            throw InvalidAuthnRequest::make('unsupported or missing SigAlg (RSA-SHA256 required)');
        }

        if ($certificatePem === null || $certificatePem === '') {
            throw InvalidAuthnRequest::make('SP has no certificate on file to verify a signed request');
        }

        $getData = [
            'SAMLRequest' => $samlRequest,
            'SigAlg' => $sigAlg,
            'Signature' => $signature,
        ];

        if ($relayState !== null && $relayState !== '') {
            $getData['RelayState'] = $relayState;
        }

        $idpData = ['x509cert' => SamlUtils::formatCert($certificatePem)];

        try {
            $valid = SamlUtils::validateBinarySign('SAMLRequest', $getData, $idpData);
        } catch (Throwable $exception) {
            throw InvalidAuthnRequest::make('request signature could not be verified ('.$exception->getMessage().')');
        }

        if ($valid !== true) {
            throw InvalidAuthnRequest::make('request signature is invalid');
        }
    }
}
