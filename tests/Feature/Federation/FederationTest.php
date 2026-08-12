<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\AccountInactive;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('creates a connection with sealed config that round-trips', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);

    $connection = $connections->create($org->id, ConnectionType::Saml, 'Okta', [
        // This fixture posts an UNSOLICITED assertion (no InResponseTo), which is now
        // opt-in per connection — see SamlAssertionValidator. Enabled here so the test
        // keeps exercising the IdP-initiated path deliberately rather than by default.
        'allow_idp_initiated' => true,
        'idp_entity_id' => 'http://www.okta.com/exk1',
        'idp_cert' => '-----BEGIN CERTIFICATE-----...',
    ]);

    expect($connection->config_encrypted)->not->toContain('okta.com')  // sealed at rest
        ->and($connections->config($connection))->toMatchArray([
            'idp_entity_id' => 'http://www.okta.com/exk1',
        ]);
});

it('parses a connection config into a typed value object, per protocol', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);

    $saml = $connections->create($org->id, ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => 'https://idp.example/entity',
        'idp_sso_url' => 'https://idp.example/sso',
        'idp_x509cert' => 'CERT-ONE',
        'idp_x509cert_extra' => ['CERT-TWO', 'CERT-ONE', 42],
        'sp_entity_id' => 'https://sp.example/metadata',
        'sp_acs_url' => 'https://sp.example/saml/acs',
        'allow_idp_initiated' => '1', // truthy-ish, but NOT the boolean true
    ]);

    $config = $connections->samlConfig($saml);

    expect($config->idpEntityId)->toBe('https://idp.example/entity')
        // The extras are filtered to strings and de-duplicated against the primary.
        ->and($config->signingCertificates())->toBe(['CERT-ONE', 'CERT-TWO'])
        // Derived, not stored: the ACS/SLO route pair stays in lockstep.
        ->and($config->slsUrl())->toBe('https://sp.example/saml/slo')
        // Opt-in means opt-in: '1' is not true, so IdP-initiated stays off.
        ->and($config->allowIdpInitiated)->toBeFalse();

    $oidc = $connections->create($org->id, ConnectionType::Oidc, 'Corp', [
        'issuer' => 'https://idp.example',
        'client_id' => 'client-abc',
        'signing_keys' => ['kid-1' => 'PEM-ONE', 'kid-2' => ''],
    ]);

    expect($connections->oidcConfig($oidc)->signingKeys)->toBe(['kid-1' => 'PEM-ONE'])
        ->and($connections->oidcConfig($oidc)->scopeString())->toBe('openid email profile');

    // Reading a connection as the wrong protocol is named, not silently mis-parsed.
    expect(fn () => $connections->oidcConfig($saml))->toThrow(InvalidAssertion::class)
        ->and(fn () => $connections->samlConfig($oidc))->toThrow(InvalidAssertion::class);
});

it('refuses to read an incomplete connection config rather than half-building settings', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);

    // A DRAFT may be incomplete — create() is the persistence boundary and does not
    // validate — but reading it for use must fail, and name the missing field.
    $draft = $connections->create($org->id, ConnectionType::Saml, 'Half-done', [
        'idp_entity_id' => 'https://idp.example/entity',
    ]);

    expect(fn () => $connections->samlConfig($draft))
        ->toThrow(InvalidAssertion::class, 'connection config missing [idp_sso_url]');
});

it('returns only the active connection for an organization', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);
    $draft = $connections->create($org->id, ConnectionType::Saml, 'Draft', []);

    expect($connections->forOrganization($org->id))->toBeNull(); // draft is not active

    $connections->activate($org->id, $draft->id);

    expect($connections->forOrganization($org->id)?->id)->toBe($draft->id)
        ->and($connections->byId($draft->id)?->isActive())->toBeTrue();
});

it('completes an SSO login: provisions user, membership and session', function (): void {
    $org = $this->makeOrganization();
    $connection = $this->makeConnection($org->id, ConnectionType::Saml);

    $principal = new FederatedPrincipal('saml', 'okta|dana', 'dana@corp.com', 'Dana', $connection->id);
    $session = app(FederationFlow::class)->completeLogin($connection, $principal);

    $user = app(Subjects::class)->findByEmail('dana@corp.com');

    expect($user)->not->toBeNull()
        ->and($session->user_id)->toBe($user?->id)
        ->and($session->amr)->toBe(['sso'])
        ->and(app(SessionManager::class)->active($session->id))->not->toBeNull()
        ->and(app(Memberships::class)->of($org->id, (string) $user?->id))->not->toBeNull();
});

it('refuses to complete login on an inactive connection', function (): void {
    $org = $this->makeOrganization();
    $connection = $this->makeConnection($org->id, ConnectionType::Saml, active: false);

    $principal = new FederatedPrincipal('saml', 'okta|dana', 'dana@corp.com');

    expect(fn () => app(FederationFlow::class)->completeLogin($connection, $principal))
        ->toThrow(ConnectionInactive::class);
});

it('refuses to complete SSO login for a deactivated account', function (): void {
    $org = $this->makeOrganization();
    $connection = $this->makeConnection($org->id, ConnectionType::Saml);
    $principal = new FederatedPrincipal('saml', 'okta|dana', 'dana@corp.com', 'Dana', $connection->id);

    // First login provisions the account; then an admin/directory disables it.
    $first = app(FederationFlow::class)->completeLogin($connection, $principal);
    app(Subjects::class)->deactivate($first->user_id);

    // The same IdP asserting the same identity must not get a fresh session.
    expect(fn () => app(FederationFlow::class)->completeLogin($connection, $principal))
        ->toThrow(AccountInactive::class);
});

it('emits a login event and records audit', function (): void {
    $org = $this->makeOrganization();
    $connection = $this->makeConnection($org->id);
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    app(FederationFlow::class)->completeLogin(
        $connection,
        new FederatedPrincipal('saml', 'okta|dana', 'dana@corp.com'),
    );

    $events->assertEmitted('user.login');
    $audit->assertRecorded('user.login');
});

it('refuses to activate a connection from another organization (IDOR)', function (): void {
    $orgA = $this->makeOrganization('A');
    $orgB = $this->makeOrganization('B');
    $connections = app(Connections::class);
    $draft = $connections->create($orgA->id, ConnectionType::Saml, 'A-draft', []);

    // Attacker (admin of B) tries to activate A's draft.
    $connections->activate($orgB->id, $draft->id);

    expect($connections->forOrganization($orgA->id))->toBeNull(); // still draft
});

/**
 * "WHICH CONNECTION DOES THIS ORGANIZATION SIGN IN WITH" IS ASKED FIVE TIMES A RENDER.
 *
 * Measured on the dashboard: the page asks, the setup checklist asks the identical
 * question again, the connectors overview a third time, and Volt runs `with()` twice. It
 * is one row that cannot change mid-request.
 *
 * The memo that fixes it is the dangerous kind — this service is a singleton, so it is
 * bounded by the request lifetime and dropped by the writes that change the answer. These
 * hold that second half, which is the one memoising introduces.
 */
it('answers the same connection question once per request', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);

    $connection = $connections->create($org->id, ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => 'https://idp.example/metadata',
        'idp_sso_url' => 'https://idp.example/sso',
        'idp_certificate' => 'cert',
    ]);
    $connections->activate($org->id, $connection->id);

    $queries = 0;
    DB::listen(function () use (&$queries): void {
        $queries++;
    });

    $connections->forOrganization($org->id);
    $connections->forOrganization($org->id);
    $connections->forOrganization($org->id);

    expect($queries)->toBe(1);
});

it('does not answer from a memo the write it just made invalidated', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);

    // Ask BEFORE there is one, so the memo holds the null.
    expect($connections->forOrganization($org->id))->toBeNull();

    $created = $connections->create($org->id, ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => 'https://idp.example/metadata',
        'idp_sso_url' => 'https://idp.example/sso',
        'idp_certificate' => 'cert',
    ]);

    // A connection is created as a DRAFT, so it is `activate()` that changes the answer —
    // which is the write the memo has to survive being wrong about.
    $connections->activate($org->id, $created->id);

    expect($connections->forOrganization($org->id)?->id)->toBe($created->id);
});

it('does not answer one organization from another organization\'s memo', function (): void {
    $a = $this->makeOrganization('A');
    $b = $this->makeOrganization('B');
    $connections = app(Connections::class);

    $connection = $connections->create($a->id, ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => 'https://idp.example/metadata',
        'idp_sso_url' => 'https://idp.example/sso',
        'idp_certificate' => 'cert',
    ]);
    $connections->activate($a->id, $connection->id);

    expect($connections->forOrganization($a->id))->not->toBeNull()
        ->and($connections->forOrganization($b->id))->toBeNull();
})->group('security');
