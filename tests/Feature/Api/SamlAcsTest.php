<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Tests\Support\SamlIdp;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const SP_METADATA = 'https://sp.example.test/metadata';
const ACS_URL = 'https://id.cbox.test/sso/saml/acs';

function samlAcsConnection(SamlIdp $idp, string $organizationId, bool $active = true): string
{
    $connections = app(Connections::class);

    $connection = $connections->create($organizationId, ConnectionType::Saml, 'Okta', [
        // This fixture posts an UNSOLICITED assertion (no InResponseTo), which is now
        // opt-in per connection — see SamlAssertionValidator. Enabled here so the test
        // keeps exercising the IdP-initiated path deliberately rather than by default.
        'allow_idp_initiated' => true,
        'idp_entity_id' => $idp->entityId,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => SP_METADATA,
        // The validator pins onelogin's Recipient/Destination check to this URL,
        // independent of the host the request actually arrives on.
        'sp_acs_url' => ACS_URL,
    ]);

    if ($active) {
        $connections->activate($connection->organization_id, $connection->id);
    }

    return $connection->id;
}

it('completes SAML SSO through the ACS endpoint and starts a session', function (): void {
    $idp = new SamlIdp;
    $org = $this->makeOrganization();
    $connectionId = samlAcsConnection($idp, $org->id);

    $response = $this->post('http://localhost/sso/saml/'.$connectionId.'/acs', [
        'SAMLResponse' => $idp->signedResponse('alice@corp.com', SP_METADATA, ACS_URL),
    ]);

    $response->assertOk()->assertJsonStructure(['session_id', 'user_id', 'organization_id']);

    $session = app(SessionManager::class)->active((string) $response->json('session_id'));
    expect($session)->not->toBeNull()
        ->and($session?->amr)->toBe(['sso'])
        ->and($session?->organization_id)->toBe($org->id);
});

it('rejects a tampered assertion at the ACS endpoint', function (): void {
    $idp = new SamlIdp;
    $org = $this->makeOrganization();
    $connectionId = samlAcsConnection($idp, $org->id);

    // A response signed by a different IdP than the connection trusts.
    $attacker = new SamlIdp;

    $this->post('http://localhost/sso/saml/'.$connectionId.'/acs', [
        'SAMLResponse' => $attacker->signedResponse('alice@corp.com', SP_METADATA, ACS_URL),
    ])->assertStatus(401);
});

it('returns 404 for an unknown connection', function (): void {
    $idp = new SamlIdp;

    $this->post('http://localhost/sso/saml/does-not-exist/acs', [
        'SAMLResponse' => $idp->signedResponse('alice@corp.com', SP_METADATA, ACS_URL),
    ])->assertStatus(404);
});

it('returns 404 for an inactive connection', function (): void {
    $idp = new SamlIdp;
    $org = $this->makeOrganization();
    $connectionId = samlAcsConnection($idp, $org->id, active: false);

    $this->post('http://localhost/sso/saml/'.$connectionId.'/acs', [
        'SAMLResponse' => $idp->signedResponse('alice@corp.com', SP_METADATA, ACS_URL),
    ])->assertStatus(404);
});

it('returns 400 when SAMLResponse is missing', function (): void {
    $idp = new SamlIdp;
    $org = $this->makeOrganization();
    $connectionId = samlAcsConnection($idp, $org->id);

    $this->post('http://localhost/sso/saml/'.$connectionId.'/acs', [])->assertStatus(400);
});
