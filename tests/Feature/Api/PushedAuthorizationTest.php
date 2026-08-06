<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\PushedAuthorizationRequests;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\PushedAuthorizationRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @return array<string, string>
 */
function parRequest(string $clientId, array $extra = []): array
{
    return array_merge([
        'client_id' => $clientId,
        'response_type' => 'code',
        'redirect_uri' => 'https://app.test/callback',
        'scope' => 'openid profile',
        'state' => 'xyz',
        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method' => 'S256',
    ], $extra);
}

it('accepts a pushed authorization request and returns a single-use request_uri', function (): void {
    $registered = $this->makeClient(['openid', 'profile']);

    $response = $this->postJson('/oauth/par', parRequest($registered->client->client_id, [
        'client_secret' => $registered->secret,
    ]));

    $response->assertStatus(201)
        ->assertJsonStructure(['request_uri', 'expires_in']);

    expect($response->json('request_uri'))->toStartWith('urn:ietf:params:oauth:request_uri:')
        ->and($response->json('expires_in'))->toBeGreaterThan(0);

    // The request was stored for this client, without the client secret.
    $record = PushedAuthorizationRequest::query()->firstOrFail();
    expect($record->client_id)->toBe($registered->client->client_id)
        ->and($record->params)->not->toHaveKey('client_secret')
        ->and($record->params['scope'])->toBe('openid profile');
});

it('consumes the request_uri exactly once for the owning client', function (): void {
    $registered = $this->makeClient(['openid']);
    $par = app(PushedAuthorizationRequests::class);

    $pushed = $par->push($registered->client, parRequest($registered->client->client_id));
    $uri = $pushed['request_uri'];

    // First consume returns the stored params; a second is refused (single-use).
    expect($par->consume($registered->client->client_id, $uri))->toMatchArray(['response_type' => 'code'])
        ->and($par->consume($registered->client->client_id, $uri))->toBeNull()
        // A different client cannot consume another's request_uri.
        ->and($par->consume('someone-else', $uri))->toBeNull();
});

it('does not consume an expired request_uri', function (): void {
    $registered = $this->makeClient(['openid']);
    $par = app(PushedAuthorizationRequests::class);

    $uri = $par->push($registered->client, parRequest($registered->client->client_id))['request_uri'];
    PushedAuthorizationRequest::query()->where('request_uri', $uri)->update(['expires_at' => now()->subMinute()]);

    expect($par->consume($registered->client->client_id, $uri))->toBeNull();
});

it('rejects an unauthenticated confidential client and a non-code response_type', function (): void {
    $registered = $this->makeClient(['openid']);

    // Wrong secret.
    $this->postJson('/oauth/par', parRequest($registered->client->client_id, ['client_secret' => 'wrong']))
        ->assertStatus(401);

    // Not the code flow.
    $this->postJson('/oauth/par', parRequest($registered->client->client_id, [
        'client_secret' => $registered->secret,
        'response_type' => 'token',
    ]))->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('requires an S256 code_challenge from a public client', function (): void {
    $public = $this->makeClient(['openid', 'profile'], ClientType::Public);

    // A public client (no secret) must prove PKCE at PAR time.
    $params = parRequest($public->client->client_id);
    unset($params['code_challenge'], $params['code_challenge_method']);

    $this->postJson('/oauth/par', $params)
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_request');

    // With the S256 challenge present it is accepted.
    $this->postJson('/oauth/par', parRequest($public->client->client_id))
        ->assertStatus(201);
});

it('advertises the PAR endpoint in the authorization-server metadata', function (): void {
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('pushed_authorization_request_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/par'))
        ->assertJsonPath('require_pushed_authorization_requests', false);
});
