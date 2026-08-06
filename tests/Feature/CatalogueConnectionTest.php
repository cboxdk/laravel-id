<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Illuminate\Foundation\Testing\RefreshDatabase;

/**
 * A tenant may enable several catalogue providers at once, while still having at most
 * one enterprise sign-on connection. Keeping those two apart is what the `provider`
 * column is for.
 */
uses(RefreshDatabase::class);

it('does not let a catalogue provider become the organization enterprise connection', function (): void {
    $connections = app(Connections::class);

    $github = $connections->create('org-1', ConnectionType::OAuth2, 'GitHub', [
        'provider' => 'github', 'client_id' => 'id', 'client_secret' => 'secret',
    ], provider: 'github');
    $connections->activate('org-1', $github->id);

    // Before the column existed, forOrganization() returned whichever active row came
    // back first. Enabling Google could silently become an organization's SSO — and an
    // organization's SSO decides where every one of its people is sent to authenticate.
    expect($connections->forOrganization('org-1'))->toBeNull();
})->group('security');

it('still returns a hand-configured connection as the enterprise one', function (): void {
    $connections = app(Connections::class);

    $enterprise = $connections->create('org-1', ConnectionType::Oidc, 'Corporate', [
        'issuer' => 'https://idp.corp', 'client_id' => 'id', 'client_secret' => 'secret',
    ]);
    $connections->activate('org-1', $enterprise->id);

    expect($connections->forOrganization('org-1')?->id)->toBe($enterprise->id);
});

it('lists a tenant catalogue providers in a stable order', function (): void {
    $connections = app(Connections::class);

    foreach ([['github', ConnectionType::OAuth2], ['google', ConnectionType::Oidc], ['discord', ConnectionType::OAuth2]] as [$key, $type]) {
        $row = $connections->create('org-1', $type, ucfirst($key), [
            'provider' => $key, 'client_id' => 'id', 'client_secret' => 'secret',
        ], provider: $key);
        $connections->activate('org-1', $row->id);
    }

    // A draft is not offered: an administrator half-way through pasting credentials must
    // not have a dead button appear on the sign-in page in the meantime.
    $connections->create('org-1', ConnectionType::OAuth2, 'Facebook', [
        'provider' => 'facebook', 'client_id' => 'id', 'client_secret' => 'secret',
    ], provider: 'facebook');

    $keys = array_map(static fn ($c): ?string => $c->provider, $connections->catalogueProvidersFor('org-1'));

    // Ordered by the column, so buttons do not rearrange between page loads or replicas.
    expect($keys)->toBe(['discord', 'github', 'google']);
});

it('does not leak one tenant providers into another', function (): void {
    $connections = app(Connections::class);

    $row = $connections->create('org-1', ConnectionType::OAuth2, 'GitHub', [
        'provider' => 'github', 'client_id' => 'id', 'client_secret' => 'secret',
    ], provider: 'github');
    $connections->activate('org-1', $row->id);

    expect($connections->catalogueProvidersFor('org-2'))->toBe([]);
})->group('security');

it('refuses a provider key the catalogue does not have', function (): void {
    // Stored, this would render a sign-in button nobody can complete — and the failure
    // would land on the person clicking it rather than on whoever typed it.
    expect(fn () => app(Connections::class)->create('org-1', ConnectionType::OAuth2, 'Nope', [
        'provider' => 'myspace', 'client_id' => 'id', 'client_secret' => 'secret',
    ], provider: 'myspace'))->toThrow(InvalidAssertion::class, 'unknown provider');
})->group('security');

it('refuses to read an OIDC provider config through the OAuth 2.0 path', function (): void {
    $connections = app(Connections::class);

    // Google speaks OIDC. Reading it as OAuth 2.0 would mean no id_token was ever
    // verified, while the connection still looked like a working Google sign-in.
    $row = $connections->create('org-1', ConnectionType::OAuth2, 'Google', [
        'provider' => 'google', 'client_id' => 'id', 'client_secret' => 'secret',
    ], provider: 'google');

    expect(fn () => $connections->oauth2Config($row))->toThrow(InvalidAssertion::class);
})->group('security');

it('round-trips an OAuth 2.0 connection config', function (): void {
    $connections = app(Connections::class);

    $row = $connections->create('org-1', ConnectionType::OAuth2, 'GitHub', [
        'provider' => 'github', 'client_id' => 'the-id', 'client_secret' => 'the-secret',
    ], provider: 'github');

    $config = $connections->oauth2Config($row);

    expect($config->provider)->toBe('github')
        ->and($config->clientId)->toBe('the-id')
        ->and($config->clientSecret)->toBe('the-secret');
});
