<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\FederationLoginService;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * SINGLE SIGN-ON WITHOUT A TENANT.
 *
 * `connections.organization_id` was NOT NULL, which made the flagship capability of an
 * identity provider unavailable to any environment that does not use organizations. An
 * internal admin tool behind Okta is an ordinary thing to want, and the only way to have
 * it was to invent a tenancy the product has no other use for — whose memberships then
 * leak meaning into everything keyed on membership.
 */
it('signs somebody in through a connection the environment owns', function (): void {
    $connection = app(Connections::class)->create(
        null,
        ConnectionType::Oidc,
        'Corporate Okta',
        ['issuer' => 'https://idp.corp', 'client_id' => 'abc', 'client_secret' => 'shh'],
    );

    app(Connections::class)->activate(null, $connection->id);

    $session = app(FederationLoginService::class)->completeLogin(
        $connection->refresh(),
        new FederatedPrincipal('oidc', 'ext-1', 'agent@acme.example', 'Agent', $connection->id),
    );

    // Signed in, and belonging to nothing — which is the point. A membership invented
    // here would put a tenancy the product never asked for into every token.
    expect($session->organization_id)->toBeNull()
        ->and(app(Memberships::class)->forUser($session->user_id))->toHaveCount(0);
});

/**
 * @group security
 *
 * Naming no organization is not a wildcard. An environment-owned connection and a
 * tenant's own are two different owners, and a caller holding one must not be able to
 * reach the other — activation is the write where that would matter most, because it
 * decides which connection an organization signs in with.
 */
it('cannot activate a tenant’s connection by naming no organization', function (): void {
    $theirs = app(Connections::class)->create(
        'org-a',
        ConnectionType::Oidc,
        'Their Okta',
        ['issuer' => 'https://idp.rival', 'client_id' => 'abc', 'client_secret' => 'shh'],
    );

    app(Connections::class)->activate(null, $theirs->id);

    expect($theirs->refresh()->isActive())->toBeFalse();
})->group('security');

/**
 * And the reverse: an environment-owned connection is not reachable by naming a tenant.
 */
it('cannot activate the environment’s connection by naming a tenant', function (): void {
    $ours = app(Connections::class)->create(
        null,
        ConnectionType::Oidc,
        'Our Okta',
        ['issuer' => 'https://idp.corp', 'client_id' => 'abc', 'client_secret' => 'shh'],
    );

    app(Connections::class)->activate('org-a', $ours->id);

    expect($ours->refresh()->isActive())->toBeFalse();
})->group('security');

/**
 * The lookup keeps them apart too — an organization with no connection of its own does
 * not silently inherit the environment's, which would sign its people in through an
 * identity provider their administrator never chose.
 */
it('does not hand the environment’s connection to an organization', function (): void {
    $ours = app(Connections::class)->create(
        null,
        ConnectionType::Oidc,
        'Our Okta',
        ['issuer' => 'https://idp.corp', 'client_id' => 'abc', 'client_secret' => 'shh'],
    );

    app(Connections::class)->activate(null, $ours->id);

    expect(app(Connections::class)->forOrganization('org-a'))->toBeNull()
        ->and(app(Connections::class)->forOrganization(null)?->id)->toBe($ours->id);
})->group('security');
