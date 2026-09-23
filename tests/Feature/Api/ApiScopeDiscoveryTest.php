<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * What a client that has never been told anything can learn and obtain: dynamic
 * registration accepts the registered scopes a self-registered client may hold, and
 * discovery advertises exactly those.
 */

beforeEach(function (): void {
    $this->makeApi('https://tax.example.test', ['tax:read', 'tax:assess' => false]);
});

// ---------------------------------------------------------------------------------------
// Dynamic client registration (RFC 7591 / 7592).
// ---------------------------------------------------------------------------------------

it('accepts registered tenant-requestable scopes at dynamic registration and drops the rest', function (): void {
    config([
        'cbox-id.oauth.dynamic_registration.mode' => 'open',
        // Listing a registered scope in the allow-list cannot widen what its API allows.
        'cbox-id.oauth.dynamic_registration.allowed_scopes' => ['openid', 'tax:assess'],
    ]);

    $response = $this->postJson('/oauth/register', [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
        'scope' => 'openid tax:read tax:assess made:up',
    ])->assertStatus(201);

    expect($response->json('scope'))->toBe('openid tax:read')
        ->and(Client::query()->where('client_id', $response->json('client_id'))->sole()->scopes)->toBe(['openid', 'tax:read']);

    // RFC 7592 update: the same rule, not a second one.
    $this->putJson('/oauth/register/'.$response->json('client_id'), [
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['authorization_code'],
        'redirect_uris' => ['https://app.test/cb'],
        'scope' => 'openid tax:assess',
    ], ['Authorization' => 'Bearer '.$response->json('registration_access_token')])
        ->assertOk()
        ->assertJsonPath('scope', 'openid');
});

// ---------------------------------------------------------------------------------------
// Discovery.
// ---------------------------------------------------------------------------------------

it('advertises the protocol scopes plus the scopes any client here may hold', function (): void {
    $org = $this->makeOrganization();
    $this->makeApi('https://books.example.test', ['books:read'], organizationId: $org->id);

    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('scopes_supported', ['openid', 'profile', 'email', 'offline_access', 'organizations', 'groups', 'tax:read']);
});
