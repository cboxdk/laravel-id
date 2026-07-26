<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Saml\SamlLogout;
use Cbox\Id\Federation\Saml\SamlSettings;
use Cbox\Id\Federation\ValueObjects\SamlConnectionConfig;
use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\Tests\Support\SamlIdp;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * The SP half of a connection, with no key material of its own before this — which
 * is what made `logoutResponseSigned` default to false, left the published SP
 * metadata without a KeyDescriptor, and made an EncryptedAssertion (what Salesforce
 * and Shibboleth send by default) impossible to read.
 */
function samlConnectionConfig(): SamlConnectionConfig
{
    return SamlConnectionConfig::fromArray([
        'idp_entity_id' => 'https://idp.okta.example/entity',
        'idp_sso_url' => 'https://idp.okta.example/sso',
        'idp_x509cert' => 'CERT-ONE',
        'sp_entity_id' => 'https://sp.example.test/metadata',
        'sp_acs_url' => 'https://sp.example.test/saml/acs',
    ]);
}

it('gives the SP role the platform key material, so it can sign and decrypt', function (): void {
    $settings = SamlSettings::toArray(samlConnectionConfig());
    $material = app(IdpKeyMaterial::class)->active();

    expect($settings['sp']['privateKey'])->toBe($material->privateKeyPem)
        ->and($settings['sp']['x509cert'])->toBe($material->certificatePem)
        // Okta/Entra with "validate logout response signature" enabled reject an
        // unsigned LogoutResponse — and the user keeps a live IdP session they
        // believe they closed.
        ->and($settings['security']['logoutResponseSigned'])->toBeTrue();
});

it('publishes a KeyDescriptor in the SP metadata php-saml builds', function (): void {
    $metadata = SamlSettings::for(samlConnectionConfig())->getSPMetadata();

    expect($metadata)->toContain('<md:KeyDescriptor')
        ->toContain('<ds:X509Certificate>');
});

/**
 * php-saml compares Destination with `strncmp`, never for equality; this flag only
 * chooses which string's length bounds the comparison. Off, a Destination that
 * EXTENDS our ACS (`…/acs?tenant=other`, `…/acs/2`) is accepted at `…/acs`. On,
 * that direction is closed — a Destination that is a PREFIX of the received URL
 * still passes, so this is the safer half of an inexact comparison, not an exact one.
 */
it('closes the Destination-extends-our-ACS half of php-saml comparison', function (): void {
    $settings = SamlSettings::toArray(samlConnectionConfig());

    expect($settings['security']['destinationStrictlyMatches'])->toBeTrue();
});

it('hands php-saml every IdP signing certificate so a rollover verifies either way', function (): void {
    $settings = SamlSettings::toArray(new SamlConnectionConfig(
        idpEntityId: 'https://idp.okta.example/entity',
        idpSsoUrl: 'https://idp.okta.example/sso',
        idpCertificate: 'CERT-ONE',
        spEntityId: 'https://sp.example.test/metadata',
        spAcsUrl: 'https://sp.example.test/saml/acs',
        idpExtraCertificates: ['CERT-TWO', 'CERT-ONE'],
    ));

    // De-duplicated, primary first — php-saml tries each in turn.
    expect($settings['idp']['x509certMulti']['signing'])->toBe(['CERT-ONE', 'CERT-TWO'])
        ->and($settings['idp']['x509cert'])->toBe('CERT-ONE');
});

it('publishes no x509certMulti when the IdP has a single signing certificate', function (): void {
    $settings = SamlSettings::toArray(samlConnectionConfig());

    expect($settings['idp'])->not->toHaveKey('x509certMulti');
});

/**
 * The payoff: an SP with key material signs the `LogoutResponse` it sends back.
 * Okta and Entra with "validate logout response signature" enabled reject an
 * unsigned one — and the user walks away believing they closed a session that is
 * still live at the IdP.
 */
it('signs the LogoutResponse it returns to the IdP', function (): void {
    $idp = new SamlIdp;
    $connections = app(Connections::class);

    $connection = $connections->create($this->makeOrganization()->id, ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => $idp->entityId,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_slo_url' => 'https://idp.example.test/slo',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => 'https://id.cbox.test/saml/metadata',
        'sp_acs_url' => 'https://id.cbox.test/sso/saml/acs',
    ]);
    $connections->activate($connection->organization_id, $connection->id);

    $result = app(SamlLogout::class)->handle(
        $connection->refresh(),
        $idp->signedLogoutRequest('alice@corp.com', 'https://id.cbox.test/sso/saml/slo'),
    );

    expect($result->error)->toBeNull()
        ->and($result->redirectUrl)->toBeString();

    parse_str((string) parse_url((string) $result->redirectUrl, PHP_URL_QUERY), $query);

    expect($query)->toHaveKeys(['SAMLResponse', 'SigAlg', 'Signature'])
        ->and($query['SigAlg'])->toBe('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');
});
