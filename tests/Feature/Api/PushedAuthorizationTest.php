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
    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('pushed_authorization_request_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/par'))
        ->assertJsonPath('require_pushed_authorization_requests', false);
});

/**
 * The pushed body cannot name a client other than the one that authenticated.
 *
 * This is the control that makes the PAR endpoint's thin validation safe. It stores
 * parameters largely as given — RFC 9126 §2.1 would have the AS validate them here, and
 * this package validates them at `/authorize` instead, which the conformance matrix grades
 * as host-supplied and which the reference console does. That division only holds while
 * `client_id` is fixed by authentication: if the stored payload could name a different
 * client, the consent page reads `client_id` from the pushed payload in preference to the
 * query, and would resolve, and validate redirect URIs against, somebody else's client.
 *
 * `push()` overwrites it. That is one line with a comment, which is exactly the kind of
 * line a later refactor drops while every existing test stays green.
 */
it('fixes client_id to the authenticated client, whatever the body says', function (): void {
    $registered = $this->makeClient();
    $victim = $this->makeClient();

    $par = app(PushedAuthorizationRequests::class);

    $pushed = $par->push($registered->client, parRequest($victim->client->client_id));

    $params = $par->consume($registered->client->client_id, $pushed['request_uri']);

    expect($params)->not->toBeNull()
        ->and($params['client_id'])->toBe($registered->client->client_id)
        ->and($params['client_id'])->not->toBe($victim->client->client_id);
})->group('security');

/**
 * …and the record is keyed to that client too, so the victim cannot redeem it either.
 */
it('refuses to hand a pushed request to a client that did not push it', function (): void {
    $registered = $this->makeClient();
    $other = $this->makeClient();

    $par = app(PushedAuthorizationRequests::class);
    $uri = $par->push($registered->client, parRequest($registered->client->client_id))['request_uri'];

    expect($par->consume($other->client->client_id, $uri))->toBeNull()
        // …and it is still there for its rightful owner: a failed lookup must not
        // consume the single use.
        ->and($par->consume($registered->client->client_id, $uri))->not->toBeNull();
})->group('security');
