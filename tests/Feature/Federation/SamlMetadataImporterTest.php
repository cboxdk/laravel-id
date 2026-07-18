<?php

declare(strict_types=1);

use Cbox\Id\Federation\Exceptions\SamlMetadataImportFailed;
use Cbox\Id\Federation\Saml\SamlMetadataImporter;
use Illuminate\Support\Facades\Http;

/** A real base64 X.509 certificate (DER, no PEM armour) — what IdP metadata embeds. */
function signingCertBase64(): string
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $csr = openssl_csr_new(['commonName' => 'idp.okta.example'], $key);
    $x509 = openssl_csr_sign($csr, null, $key, 1);
    openssl_x509_export($x509, $pem);

    // Strip the PEM armour and newlines — metadata carries the bare base64 DER.
    $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);

    return is_string($body) ? $body : '';
}

/** An Okta/Entra-shaped IdP metadata document. */
function idpMetadataXml(string $cert, bool $withSlo = true): string
{
    $slo = $withSlo
        ? '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.okta.example/slo"/>'
        : '';

    return <<<XML
    <?xml version="1.0" encoding="UTF-8"?>
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.okta.example/entity">
      <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:X509Data><ds:X509Certificate>{$cert}</ds:X509Certificate></ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        {$slo}
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.okta.example/sso"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.okta.example/sso-post"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    XML;
}

it('imports a real IdP metadata document into a connection prefill', function (): void {
    $cert = signingCertBase64();

    $metadata = app(SamlMetadataImporter::class)->fromXml(idpMetadataXml($cert));

    expect($metadata->isComplete())->toBeTrue()
        ->and($metadata->entityId)->toBe('https://idp.okta.example/entity')
        // Prefers the HTTP-Redirect binding for SSO.
        ->and($metadata->ssoUrl)->toBe('https://idp.okta.example/sso')
        ->and($metadata->sloUrl)->toBe('https://idp.okta.example/slo')
        ->and($metadata->x509cert)->toBe($cert);

    // Maps onto exactly the keys the SAML validator/settings require.
    expect($metadata->toConfig())->toBe([
        'idp_entity_id' => 'https://idp.okta.example/entity',
        'idp_sso_url' => 'https://idp.okta.example/sso',
        'idp_x509cert' => $cert,
        'idp_slo_url' => 'https://idp.okta.example/slo',
    ]);
});

it('omits the SLO key when the IdP publishes no SingleLogoutService', function (): void {
    $metadata = app(SamlMetadataImporter::class)->fromXml(idpMetadataXml(signingCertBase64(), withSlo: false));

    expect($metadata->sloUrl)->toBeNull()
        ->and($metadata->toConfig())->not->toHaveKey('idp_slo_url');
});

it('rejects malformed XML', function (): void {
    expect(fn () => app(SamlMetadataImporter::class)->fromXml('<not-metadata>'))
        ->toThrow(SamlMetadataImportFailed::class);
});

it('rejects a document with no IDPSSODescriptor', function (): void {
    $xml = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/></md:EntityDescriptor>';

    expect(fn () => app(SamlMetadataImporter::class)->fromXml($xml))
        ->toThrow(SamlMetadataImportFailed::class);
});

it('rejects metadata missing the signing certificate', function (): void {
    $xml = '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>';

    expect(fn () => app(SamlMetadataImporter::class)->fromXml($xml))
        ->toThrow(SamlMetadataImportFailed::class, 'missing');
});

it('fetches metadata from a URL through the SSRF gate', function (): void {
    // Disable URL enforcement so the fake host isn't DNS-resolved (as the flow tests do).
    config(['cbox-id.federation.verify_url' => false]);

    $cert = signingCertBase64();
    Http::fake(['idp.okta.example/*' => Http::response(idpMetadataXml($cert), 200)]);

    $metadata = app(SamlMetadataImporter::class)->fromUrl('https://idp.okta.example/metadata.xml');

    expect($metadata->entityId)->toBe('https://idp.okta.example/entity')
        ->and($metadata->x509cert)->toBe($cert);
});

it('surfaces an HTTP error from a metadata URL', function (): void {
    config(['cbox-id.federation.verify_url' => false]);
    Http::fake(['idp.okta.example/*' => Http::response('nope', 404)]);

    expect(fn () => app(SamlMetadataImporter::class)->fromUrl('https://idp.okta.example/metadata.xml'))
        ->toThrow(SamlMetadataImportFailed::class, 'HTTP 404');
});
