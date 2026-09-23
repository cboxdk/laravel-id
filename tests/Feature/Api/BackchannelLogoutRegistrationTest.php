<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * `backchannel_logout_uri` and `backchannel_logout_session_required` (OIDC Back-Channel
 * Logout 1.0 §2.2), through every door a client's metadata comes in by: the registry,
 * the registry's update, and Dynamic Client Registration.
 */

function registerWithBackchannel(?string $uri, bool $sessionRequired = false): Client
{
    return app(ClientRegistry::class)->register(new NewClient(
        'RP',
        ClientType::Confidential,
        redirectUris: ['https://rp.example/cb'],
        grantTypes: ['authorization_code'],
        scopes: ['openid'],
        backchannelLogoutUri: $uri,
        backchannelLogoutSessionRequired: $sessionRequired,
    ))->client;
}

it('stores the back-channel logout metadata a client registers with', function (): void {
    $client = registerWithBackchannel('https://rp.example/logout?tenant=a', true)->refresh();

    expect($client->backchannel_logout_uri)->toBe('https://rp.example/logout?tenant=a')
        ->and($client->backchannel_logout_session_required)->toBeTrue();
});

it('registers nothing by default, so no existing client starts being called', function (): void {
    $client = registerWithBackchannel(null)->refresh();

    expect($client->backchannel_logout_uri)->toBeNull()
        ->and($client->backchannel_logout_session_required)->toBeFalse();
});

it('accepts plain http only on localhost', function (string $uri): void {
    expect(registerWithBackchannel($uri)->backchannel_logout_uri)->toBe($uri);
})->with([
    'localhost' => ['http://localhost:8000/logout'],
    'IPv4 loopback' => ['http://127.0.0.1:8000/logout'],
    'IPv6 loopback' => ['http://[::1]:8000/logout'],
]);

it('refuses a URI this server will not call', function (string $uri, string $reason): void {
    expect(fn () => registerWithBackchannel($uri))
        ->toThrow(InvalidClientMetadata::class, $reason);

    expect(Client::query()->count())->toBe(0);
})->with([
    'plain http' => ['http://rp.example/logout', 'must use https (or http on localhost)'],
    'relative' => ['/logout', 'is not an absolute URI'],
    'no host' => ['https:///logout', 'is not an absolute URI'],
    'a fragment' => ['https://rp.example/logout#frag', 'must not contain a fragment'],
    'credentials' => ['https://trusted.example@evil.example/logout', 'must not contain credentials'],
    'custom scheme' => ['com.example.app://logout', 'must use https (or http on localhost)'],
    'javascript' => ['javascript://rp.example/%0aalert(1)', 'must use https (or http on localhost)'],
])->group('security');

it('sets, changes and clears the URI on an existing client', function (): void {
    $registry = app(ClientRegistry::class);
    $client = registerWithBackchannel(null);

    $registry->configureBackchannelLogout($client, 'https://rp.example/logout', true);

    expect($client->refresh()->backchannel_logout_uri)->toBe('https://rp.example/logout')
        ->and($client->backchannel_logout_session_required)->toBeTrue();

    // A cleared console field arrives as an empty string: that is "off", and the
    // requirement goes with the URI it applied to.
    $registry->configureBackchannelLogout($client, '', true);

    expect($client->refresh()->backchannel_logout_uri)->toBeNull()
        ->and($client->backchannel_logout_session_required)->toBeFalse();
});

it('validates an update exactly as it validates a registration', function (): void {
    $client = registerWithBackchannel('https://rp.example/logout');

    expect(fn () => app(ClientRegistry::class)->configureBackchannelLogout($client, 'http://rp.example/logout'))
        ->toThrow(InvalidClientMetadata::class, 'must use https');

    expect($client->refresh()->backchannel_logout_uri)->toBe('https://rp.example/logout');
})->group('security');

// ---------------------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591 / 7592)
// ---------------------------------------------------------------------------------------

it('registers back-channel logout through DCR and echoes it back', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'RP',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://rp.example/cb'],
        'scope' => 'openid',
        'backchannel_logout_uri' => 'https://rp.example/logout',
        'backchannel_logout_session_required' => true,
    ])->assertCreated()
        ->assertJsonPath('backchannel_logout_uri', 'https://rp.example/logout')
        ->assertJsonPath('backchannel_logout_session_required', true);

    $client = Client::query()->where('client_id', $response->json('client_id'))->sole();

    expect($client->backchannel_logout_uri)->toBe('https://rp.example/logout')
        ->and($client->backchannel_logout_session_required)->toBeTrue();
});

it('leaves the metadata out of the document when a client did not register it', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'RP',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://rp.example/cb'],
    ])->assertCreated();

    expect($response->json())->not->toHaveKey('backchannel_logout_uri')
        ->and($response->json())->not->toHaveKey('backchannel_logout_session_required');
});

it('refuses bad back-channel metadata at DCR, out loud', function (array $metadata, string $reason): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);

    $this->postJson('/oauth/register', [
        'client_name' => 'RP',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://rp.example/cb'],
        ...$metadata,
    ])->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata')
        ->assertJsonPath('error_description', fn (string $description): bool => str_contains($description, $reason));

    expect(Client::query()->count())->toBe(0);
})->with([
    'plain http' => [['backchannel_logout_uri' => 'http://rp.example/logout'], 'must use https'],
    'a fragment' => [['backchannel_logout_uri' => 'https://rp.example/logout#x'], 'must not contain a fragment'],
    'not a string' => [['backchannel_logout_uri' => ['https://rp.example/logout']], 'must be a non-empty string'],
    'required is not a boolean' => [['backchannel_logout_uri' => 'https://rp.example/logout', 'backchannel_logout_session_required' => 'yes'], 'must be a boolean'],
    'required without a URI' => [['backchannel_logout_session_required' => true], 'needs a backchannel_logout_uri'],
])->group('security');

it('replaces the metadata on an RFC 7592 update, so omitting it turns notifications off', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);

    $created = $this->postJson('/oauth/register', [
        'client_name' => 'RP',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://rp.example/cb'],
        'backchannel_logout_uri' => 'https://rp.example/logout',
    ])->assertCreated();

    $clientId = $created->json('client_id');
    $auth = ['Authorization' => 'Bearer '.$created->json('registration_access_token')];

    $this->putJson('/oauth/register/'.$clientId, [
        'client_id' => $clientId,
        'client_name' => 'RP',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://rp.example/cb'],
    ], $auth)->assertOk();

    expect(Client::query()->where('client_id', $clientId)->value('backchannel_logout_uri'))->toBeNull();
});
