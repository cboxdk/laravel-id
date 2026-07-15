<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Testing;

use Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use OneLogin\Saml2\Response as OneLoginResponse;
use OneLogin\Saml2\Settings as OneLoginSettings;
use OneLogin\Saml2\Utils as SamlUtils;
use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RuntimeException;

/**
 * Test helpers for the SAML IdP: register relying SPs, forge AuthnRequests, and —
 * critically — validate an issued Response with onelogin/php-saml acting as the SP,
 * so the suite proves a real, independent verifier accepts the assertion.
 */
trait InteractsWithSamlIdp
{
    protected function samlIdp(): SamlIdentityProvider
    {
        return app(SamlIdentityProvider::class);
    }

    /**
     * @param  array<string, string>  $attributeMappings
     */
    protected function registerSamlServiceProvider(
        string $entityId = 'https://sp.example.test/metadata',
        string $acsUrl = 'https://sp.example.test/acs',
        array $attributeMappings = ['email' => 'email', 'displayName' => 'name'],
        ?string $certificate = null,
        bool $wantAuthnRequestsSigned = false,
        NameIdFormat $nameIdFormat = NameIdFormat::EmailAddress,
        string $nameIdAttribute = 'email',
    ): ServiceProvider {
        return app(ServiceProviders::class)->register(new NewServiceProvider(
            entityId: $entityId,
            acsUrl: $acsUrl,
            nameIdFormat: $nameIdFormat,
            nameIdAttribute: $nameIdAttribute,
            attributeMappings: $attributeMappings,
            certificate: $certificate,
            wantAuthnRequestsSigned: $wantAuthnRequestsSigned,
        ));
    }

    /**
     * Build a base64+DEFLATE `SAMLRequest` (HTTP-Redirect binding) for the given SP.
     * Pass `$acsUrl` to include an AssertionConsumerServiceURL (used to exercise the
     * ACS-mismatch guard); omit it to send a request with no requested ACS.
     */
    protected function makeRedirectAuthnRequest(string $issuer, ?string $acsUrl = null, string $id = '_testreq0000000000000000000000000000'): string
    {
        $xml = $this->authnRequestXml($issuer, $id, $acsUrl);

        $deflated = gzdeflate($xml);

        return base64_encode($deflated !== false ? $deflated : $xml);
    }

    /**
     * The raw `<samlp:AuthnRequest>` XML both bindings share, with its own namespace
     * declarations on the root so it canonicalizes self-contained.
     */
    protected function authnRequestXml(string $issuer, string $id = '_testreq0000000000000000000000000000', ?string $acsUrl = null): string
    {
        $acsAttr = $acsUrl !== null ? ' AssertionConsumerServiceURL="'.htmlspecialchars($acsUrl, ENT_QUOTES).'"' : '';

        return '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            .' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            .' ID="'.htmlspecialchars($id, ENT_QUOTES).'" Version="2.0" IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'"'
            .$acsAttr.'>'
            .'<saml:Issuer>'.htmlspecialchars($issuer, ENT_QUOTES).'</saml:Issuer>'
            .'<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>'
            .'</samlp:AuthnRequest>';
    }

    /**
     * Generate an ephemeral RSA-2048 keypair with a self-signed X.509 certificate,
     * for driving the signed-request paths (the redirect binary signature or the
     * embedded POST-binding XML-DSig).
     *
     * @return array{certificate: string, privateKey: string}
     */
    protected function samlSigningKeypair(string $commonName = 'sp.example.test'): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        if (! $key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('could not generate an RSA keypair');
        }

        // openssl_csr_new takes the key by reference; re-narrow it afterwards.
        $csr = openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256']);

        if (! $csr instanceof OpenSSLCertificateSigningRequest || ! $key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('could not generate a certificate signing request');
        }

        $signed = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256'], 1);

        if (! $signed instanceof OpenSSLCertificate) {
            throw new RuntimeException('could not self-sign the certificate');
        }

        $privateKey = '';
        openssl_pkey_export($key, $privateKey);

        $certificate = '';
        openssl_x509_export($signed, $certificate);

        if (! is_string($privateKey) || $privateKey === '' || ! is_string($certificate) || $certificate === '') {
            throw new RuntimeException('could not export the generated keypair');
        }

        return ['certificate' => $certificate, 'privateKey' => $privateKey];
    }

    /**
     * Build a base64 POST-binding `SAMLRequest` carrying an enveloped RSA XML-DSig
     * over the AuthnRequest root, signed with the given private key. POST payloads
     * are base64 only (no DEFLATE). The algorithms default to RSA-SHA256 / SHA-256;
     * override them to drive the algorithm-pin rejection paths (e.g. SHA-1).
     */
    protected function makeSignedPostAuthnRequest(
        string $issuer,
        string $privateKey,
        string $certificate,
        ?string $acsUrl = null,
        string $id = '_postreq00000000000000000000000000000',
        string $signatureAlgorithm = XMLSecurityKey::RSA_SHA256,
        string $digestAlgorithm = XMLSecurityDSig::SHA256,
    ): string {
        $signed = SamlUtils::addSign(
            $this->authnRequestXml($issuer, $id, $acsUrl),
            $privateKey,
            SamlUtils::formatCert($certificate),
            $signatureAlgorithm,
            $digestAlgorithm,
        );

        return base64_encode($signed);
    }

    /**
     * Validate an issued Response the way the SP would: build onelogin settings from
     * the IdP's published certificate and the SP's ACS/entity id, then run
     * onelogin's full validation (signature, audience, recipient, InResponseTo,
     * conditions). Returns the onelogin Response so the caller can assert on it.
     *
     * @return array{0: OneLoginResponse, 1: bool}
     */
    protected function validateWithOnelogin(
        string $encodedResponse,
        ServiceProvider $serviceProvider,
        string $idpEntityId,
        string $idpCertificatePem,
        ?string $expectedInResponseTo,
    ): array {
        $settings = new OneLoginSettings([
            'strict' => true,
            'sp' => [
                'entityId' => $serviceProvider->entity_id,
                'assertionConsumerService' => ['url' => $serviceProvider->acs_url],
            ],
            'idp' => [
                'entityId' => $idpEntityId,
                'singleSignOnService' => ['url' => $idpEntityId.'/sso'],
                'x509cert' => $idpCertificatePem,
            ],
            'security' => [
                'wantAssertionsSigned' => true,
                'wantMessagesSigned' => false,
                'requestedAuthnContext' => false,
                'wantNameId' => true,
            ],
        ]);

        return $this->withPinnedAcs($serviceProvider->acs_url, static function () use ($settings, $encodedResponse, $expectedInResponseTo): array {
            $response = new OneLoginResponse($settings, $encodedResponse);

            return [$response, $response->isValid($expectedInResponseTo)];
        });
    }

    /**
     * Pin the $_SERVER values onelogin reads to derive "the current URL" (which it
     * checks Destination/Recipient against) to the SP's ACS, for the duration of the
     * callback — the same technique the RP-side validator uses.
     *
     * @param  callable(): array{0: OneLoginResponse, 1: bool}  $callback
     * @return array{0: OneLoginResponse, 1: bool}
     */
    private function withPinnedAcs(string $acsUrl, callable $callback): array
    {
        $parts = parse_url($acsUrl);
        $parts = is_array($parts) ? $parts : [];

        $host = is_string($parts['host'] ?? null) ? $parts['host'] : 'localhost';
        $scheme = ($parts['scheme'] ?? null) === 'http' ? 'http' : 'https';
        $path = is_string($parts['path'] ?? null) ? $parts['path'] : '/';
        if (isset($parts['port'])) {
            $host .= ':'.$parts['port'];
        }

        $keys = ['HTTP_HOST', 'HTTPS', 'SCRIPT_NAME', 'PATH_INFO', 'REQUEST_URI', 'SERVER_PORT'];
        $saved = [];
        foreach ($keys as $key) {
            $saved[$key] = $_SERVER[$key] ?? null;
        }

        SamlUtils::setBaseURL('');
        $_SERVER['HTTP_HOST'] = $host;
        $_SERVER['HTTPS'] = $scheme === 'https' ? 'on' : 'off';
        $_SERVER['SCRIPT_NAME'] = $path;
        $_SERVER['REQUEST_URI'] = $path;
        unset($_SERVER['PATH_INFO'], $_SERVER['SERVER_PORT']);

        try {
            return $callback();
        } finally {
            foreach ($saved as $key => $value) {
                if ($value === null) {
                    unset($_SERVER[$key]);
                } else {
                    $_SERVER[$key] = $value;
                }
            }
        }
    }
}
