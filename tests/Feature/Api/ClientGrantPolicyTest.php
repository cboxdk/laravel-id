<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Two defects that were individually bad and, chained, let an attacker holding only a
 * client_id obtain a token having presented no credential at all:
 *
 *  - ClientAuthenticator keyed its "no secret needed" bypass on secret_hash === null.
 *    A confidential client authenticating by private_key_jwt has no stored secret BY
 *    DESIGN, so it authenticated on a client_id alone.
 *  - grant_types was stored and echoed back at registration but enforced nowhere, so
 *    any client could use any grant.
 */
it('refuses a private_key_jwt client that presents no assertion', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'JWKS client',
        ClientType::Confidential,
        grantTypes: ['client_credentials'],
        scopes: ['api.read'],
        // A JWKS client is issued NO secret — which is exactly the case the old
        // secret-presence test waved through.
        jwks: ['keys' => []],
    ));

    expect($registered->client->secret_hash)->toBeNull();

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('refuses a grant the client did not register for', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'Code-only client',
        ClientType::Confidential,
        grantTypes: ['authorization_code'],
        scopes: ['api.read'],
    ));

    // Correct credentials, wrong grant: RFC 6749 §5.2 unauthorized_client.
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
});

it('closes the chain: a client_id alone buys nothing', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'JWKS client',
        ClientType::Confidential,
        grantTypes: ['authorization_code'],
        scopes: ['api.read'],
        jwks: ['keys' => []],
    ));

    // No secret, no assertion, and a grant it never registered for. Before the fixes
    // this combination issued a working access token.
    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('still issues to a confidential client using a grant it registered', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'Machine client',
        ClientType::Confidential,
        grantTypes: ['client_credentials'],
        scopes: ['api.read'],
    ));

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'api.read',
    ])->assertOk()->assertJsonStructure(['access_token', 'token_type', 'expires_in']);
});

/**
 * RFC 6749 §5.1 / RFC 7662 §2.2 make no-store a MUST on any response carrying a
 * credential. Without it a shared proxy, a CDN that caches POSTs, or a back-button
 * replay can hand someone else's token to a second party.
 */
it('never lets a credential-bearing response be cached', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'Machine client',
        ClientType::Confidential,
        grantTypes: ['client_credentials'],
        scopes: ['api.read'],
    ));

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ])->assertOk();

    expect($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($response->headers->get('Pragma'))->toBe('no-cache');

    // Errors carry credentials-adjacent detail too, and are equally cacheable.
    $this->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => 'nope'])
        ->assertStatus(401);

    // Laravel appends `private`; what matters is that no-store is asserted present.
    expect($this->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => 'nope'])
        ->headers->get('Cache-Control'))->toContain('no-store');
});

it('explains an invalid_grant instead of returning five opaque words', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient(
        'Code client',
        ClientType::Confidential,
        grantTypes: ['refresh_token'],
        scopes: ['api.read'],
    ));

    $body = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'refresh_token' => 'rt_does_not_exist',
    ])->assertStatus(400)->json();

    // The code stays strictly RFC-valued; the description is what a developer reads.
    expect($body['error'])->toBe('invalid_grant')
        ->and($body)->toHaveKey('error_description')
        ->and($body['error_description'])->not->toBe('');
});
