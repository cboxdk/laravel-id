<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\FederationFlow;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\ConnectionInactive;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates a connection with sealed config that round-trips', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);

    $connection = $connections->create($org->id, ConnectionType::Saml, 'Okta', [
        'idp_entity_id' => 'http://www.okta.com/exk1',
        'idp_cert' => '-----BEGIN CERTIFICATE-----...',
    ]);

    expect($connection->config_encrypted)->not->toContain('okta.com')  // sealed at rest
        ->and($connections->config($connection))->toMatchArray([
            'idp_entity_id' => 'http://www.okta.com/exk1',
        ]);
});

it('returns only the active connection for an organization', function (): void {
    $org = $this->makeOrganization();
    $connections = app(Connections::class);
    $draft = $connections->create($org->id, ConnectionType::Saml, 'Draft', []);

    expect($connections->forOrganization($org->id))->toBeNull(); // draft is not active

    $connections->activate($draft->id);

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
