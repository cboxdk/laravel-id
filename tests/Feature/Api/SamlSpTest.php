<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Tests\Support\SamlIdp;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * A connection that trusts $idp, so a message it signs (Response or LogoutRequest)
 * validates against the stored cert.
 */
function samlConnectionFor(SamlIdp $idp, string $organizationId): string
{
    $connections = app(Connections::class);
    $connection = $connections->create($organizationId, ConnectionType::Saml, 'Okta', [
        // This fixture posts an UNSOLICITED assertion (no InResponseTo), which is now
        // opt-in per connection — see SamlAssertionValidator. Enabled here so the test
        // keeps exercising the IdP-initiated path deliberately rather than by default.
        'allow_idp_initiated' => true,
        'idp_entity_id' => $idp->entityId,
        'idp_sso_url' => IDP_SSO,
        'idp_slo_url' => IDP_SLO,
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => SP_ENTITY_ID,
        'sp_acs_url' => SP_ACS,
    ]);
    $connections->activate($connection->organization_id, $connection->id);

    return $connection->id;
}

const IDP_SLO = 'https://idp.example.test/slo';
const SLO_DESTINATION = 'https://id.cbox.test/sso/saml/slo';

const SP_ENTITY_ID = 'https://id.cbox.test/saml/metadata';
const SP_ACS = 'https://id.cbox.test/sso/saml/acs';
const IDP_SSO = 'https://idp.example.test/sso';

function samlSpConnection(string $organizationId, bool $active = true, array $extra = []): string
{
    $idp = new SamlIdp;
    $connections = app(Connections::class);

    $connection = $connections->create($organizationId, ConnectionType::Saml, 'Okta', array_merge([
        // This fixture posts an UNSOLICITED assertion (no InResponseTo), which is now
        // opt-in per connection — see SamlAssertionValidator. Enabled here so the test
        // keeps exercising the IdP-initiated path deliberately rather than by default.
        'allow_idp_initiated' => true,
        'idp_entity_id' => $idp->entityId,
        'idp_sso_url' => IDP_SSO,
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => SP_ENTITY_ID,
        'sp_acs_url' => SP_ACS,
    ], $extra));

    if ($active) {
        $connections->activate($connection->organization_id, $connection->id);
    }

    return $connection->id;
}

it('publishes SP metadata for a SAML connection', function (): void {
    $id = samlSpConnection($this->makeOrganization()->id);

    $response = $this->get('http://localhost/sso/saml/'.$id.'/metadata');

    $response->assertOk();
    expect($response->headers->get('Content-Type'))->toContain('application/samlmetadata+xml');

    $xml = $response->getContent();
    expect($xml)->toContain('entityID="'.SP_ENTITY_ID.'"')
        ->toContain(SP_ACS)                               // ACS endpoint advertised
        ->toContain('SingleLogoutService')                // SLO endpoint advertised
        ->toContain('WantAssertionsSigned="true"');       // our RP policy
});

it('returns 404 metadata for a non-SAML or unknown connection', function (): void {
    $this->get('http://localhost/sso/saml/nope/metadata')->assertStatus(404);
});

it('SP-initiates login with a redirect to the IdP carrying a SAMLRequest', function (): void {
    $id = samlSpConnection($this->makeOrganization()->id);

    $response = $this->get('http://localhost/sso/saml/'.$id.'/login?relay=%2Fdashboard');

    $response->assertRedirect();
    $location = $response->headers->get('Location');

    expect($location)->toStartWith(IDP_SSO.'?');
    parse_str((string) parse_url((string) $location, PHP_URL_QUERY), $query);
    expect($query)->toHaveKey('SAMLRequest')
        ->and($query['RelayState'] ?? null)->toBe('/dashboard');

    // The AuthnRequest id is remembered for the ACS InResponseTo check.
    expect(session()->get('cbox.saml_authn_request_id'))->toBeString();
});

it('does not SP-initiate login for an inactive connection', function (): void {
    $id = samlSpConnection($this->makeOrganization()->id, active: false);

    $this->get('http://localhost/sso/saml/'.$id.'/login')->assertStatus(404);
});

it('IdP-initiated SLO validates the signed LogoutRequest and revokes the subject sessions', function (): void {
    $idp = new SamlIdp;
    $org = $this->makeOrganization();
    $connectionId = samlConnectionFor($idp, $org->id);

    // Log Alice in over SAML so she has an identity link + an active session.
    $login = $this->post('http://localhost/sso/saml/'.$connectionId.'/acs', [
        'SAMLResponse' => $idp->signedResponse('alice@corp.com', SP_ENTITY_ID, SP_ACS),
    ])->assertOk();

    $userId = (string) $login->json('user_id');
    expect(Session::query()->where('user_id', $userId)->whereNull('revoked_at')->count())->toBe(1);

    // The IdP sends a signed LogoutRequest for Alice to the SLO endpoint.
    $slo = $idp->signedLogoutRequest('alice@corp.com', SLO_DESTINATION);
    $response = $this->get('http://localhost/sso/saml/'.$connectionId.'/slo?'.http_build_query($slo));

    // A LogoutResponse redirect goes back to the IdP, and Alice's session is gone.
    $response->assertRedirect();
    expect(Session::query()->where('user_id', $userId)->whereNull('revoked_at')->count())->toBe(0);
});

it('rejects an unsigned LogoutRequest at the SLO endpoint', function (): void {
    $idp = new SamlIdp;
    $org = $this->makeOrganization();
    $connectionId = samlConnectionFor($idp, $org->id);

    $this->post('http://localhost/sso/saml/'.$connectionId.'/acs', [
        'SAMLResponse' => $idp->signedResponse('alice@corp.com', SP_ENTITY_ID, SP_ACS),
    ])->assertOk();

    // Same LogoutRequest, but strip the signature — SLO must reject it so nobody
    // can force a logout without the IdP's key.
    $slo = $idp->signedLogoutRequest('alice@corp.com', SLO_DESTINATION);
    $userId = (string) IdentityLink::query()->where('subject', 'alice@corp.com')->value('user_id');

    $this->get('http://localhost/sso/saml/'.$connectionId.'/slo?'.http_build_query(['SAMLRequest' => $slo['SAMLRequest']]))
        ->assertStatus(400);

    expect(Session::query()->where('user_id', $userId)->whereNull('revoked_at')->count())->toBe(1);
});
