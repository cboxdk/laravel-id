<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function openDcr(): void
{
    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);
}

it('refuses registration when DCR is disabled (secure by default)', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'disabled']);

    $this->postJson('/oauth/register', [
        'client_name' => 'MCP Client',
        'redirect_uris' => ['https://app.test/cb'],
    ])
        ->assertStatus(403)
        ->assertJsonPath('error', 'access_denied');
});

it('registers a public client via RFC 7591 and returns a registration access token', function (): void {
    openDcr();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'MCP CLI',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['http://127.0.0.1:8765/callback'],
        'scope' => 'openid profile email',
    ])->assertStatus(201);

    $response
        ->assertJsonPath('token_endpoint_auth_method', 'none')
        ->assertJsonPath('client_name', 'MCP CLI')
        ->assertJsonPath('grant_types', ['authorization_code'])
        ->assertJsonPath('redirect_uris', ['http://127.0.0.1:8765/callback'])
        ->assertJsonStructure(['client_id', 'client_id_issued_at', 'registration_access_token', 'registration_client_uri']);

    // Public clients get no secret.
    expect($response->json('client_secret'))->toBeNull()
        ->and(Client::query()->where('client_id', $response->json('client_id'))->exists())->toBeTrue();
});

it('registers a confidential client with a secret when auth method is not none', function (): void {
    openDcr();

    $response = $this->postJson('/oauth/register', [
        'client_name' => 'Backend service',
        'grant_types' => ['client_credentials'],
        'scope' => 'openid',
    ])->assertStatus(201);

    expect($response->json('client_secret'))->toBeString()
        ->and($response->json('client_secret_expires_at'))->toBe(0);
});

it('reduces requested scopes to the configured allow-list', function (): void {
    openDcr();
    config(['cbox-id.oauth.dynamic_registration.allowed_scopes' => ['openid', 'email']]);

    $response = $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
        'scope' => 'openid email admin superuser',
    ])->assertStatus(201);

    expect($response->json('scope'))->toBe('openid email');
});

it('rejects a redirect_uri that is not https or loopback', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['http://evil.test/cb'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('registers a native app with private-use URI scheme redirects (both forms)', function (): void {
    openDcr();

    // RFC 8252 §7.1 — a native app registers a custom scheme in either the
    // authority form (com.example.app://cb) or the canonical path form
    // (com.example.app:/cb). Both must be accepted (AppAuth defaults to the latter).
    $uris = ['com.example.app://oauth2redirect', 'com.example.app:/oauth2redirect'];

    $this->postJson('/oauth/register', [
        'client_name' => 'iOS app',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => $uris,
    ])
        ->assertStatus(201)
        ->assertJsonPath('redirect_uris', $uris)
        ->assertJsonPath('token_endpoint_auth_method', 'none');
});

it('rejects a redirect_uri containing a fragment', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb#frag'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('requires redirect_uris for the authorization_code grant', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
});

it('rejects a grant_type outside the allow-list', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'grant_types' => ['password'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('rejects a public client asking for client_credentials', function (): void {
    openDcr();

    $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['client_credentials'],
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('gates protected mode on the initial access token', function (): void {
    config([
        'cbox-id.oauth.dynamic_registration.mode' => 'protected',
        'cbox-id.oauth.dynamic_registration.initial_access_token' => 'iat-secret-123',
    ]);

    // No token → 401.
    $this->postJson('/oauth/register', ['grant_types' => ['client_credentials']])
        ->assertStatus(401);

    // Correct token → 201.
    $this->withHeader('Authorization', 'Bearer iat-secret-123')
        ->postJson('/oauth/register', ['grant_types' => ['client_credentials']])
        ->assertStatus(201);
});

it('reads and deletes a client via the RFC 7592 registration access token', function (): void {
    openDcr();

    $created = $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
    ])->assertStatus(201);

    $clientId = $created->json('client_id');
    $regToken = $created->json('registration_access_token');
    $auth = ['Authorization' => 'Bearer '.$regToken];

    // Read.
    $this->getJson('/oauth/register/'.$clientId, $auth)
        ->assertOk()
        ->assertJsonPath('client_id', $clientId);

    // Wrong token is refused.
    $this->getJson('/oauth/register/'.$clientId, ['Authorization' => 'Bearer wrong'])
        ->assertStatus(401);

    // Delete, then it is gone.
    $this->deleteJson('/oauth/register/'.$clientId, [], $auth)->assertNoContent();
    expect(Client::query()->where('client_id', $clientId)->exists())->toBeFalse();
});

it('advertises the registration endpoint in discovery only when enabled', function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'disabled']);
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonMissingPath('registration_endpoint');

    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('registration_endpoint', rtrim(url('/'), '/').'/oauth/register');
});
