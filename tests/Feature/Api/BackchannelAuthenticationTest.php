<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const CIBA_GRANT = 'urn:openid:params:grant-type:ciba';

it('starts a CIBA flow and returns only the client-facing auth_req_id', function (): void {
    $registered = $this->makeClient(['openid']);
    $user = $this->makeUser('alice@example.test');

    $response = $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => $user->id,
        'binding_message' => 'Approve deployment',
    ]);

    $response->assertOk()->assertJsonStructure(['auth_req_id', 'expires_in', 'interval']);

    expect($response->json('auth_req_id'))->toStartWith('auth_req_')
        // The internal approval handle is never leaked to the client.
        ->and($response->json())->not->toHaveKey('request_id')
        ->and($response->json())->not->toHaveKey('user_id');
});

it('polls pending, then issues access + id_token once the user approves', function (): void {
    $registered = $this->makeClient(['openid']);
    $user = $this->makeUser('bob@example.test');

    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($registered->client, ['openid'], $user->id);

    // While unapproved, the token endpoint answers authorization_pending.
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertStatus(400)->assertJsonPath('error', 'authorization_pending');

    // The user approves out-of-band, via the host's approval surface (internal id).
    expect($ciba->approve($result->requestId, 'org-1'))->toBeTrue();

    // Skip the polling interval so the next poll isn't slow_down'd.
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $token = $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertOk();

    // CIBA is OIDC: an id_token is returned alongside the access token.
    expect($token->json('id_token'))->toBeString()->not->toBe('');

    $introspection = app(TokenIntrospector::class)->introspect((string) $token->json('access_token'));
    expect($introspection->active)->toBeTrue()
        ->and($introspection->subject)->toBe($user->id);
});

it('returns slow_down when polling faster than the interval', function (): void {
    $registered = $this->makeClient(['openid']);
    $user = $this->makeUser('carol@example.test');
    $result = app(BackchannelAuthentication::class)->request($registered->client, ['openid'], $user->id);

    $poll = fn () => $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ]);

    $poll()->assertJsonPath('error', 'authorization_pending'); // first poll allowed
    $poll()->assertJsonPath('error', 'slow_down');             // immediate re-poll throttled
});

it('reports denial and expiry', function (): void {
    $registered = $this->makeClient(['openid']);
    $user = $this->makeUser('dave@example.test');
    $ciba = app(BackchannelAuthentication::class);

    $denied = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->deny($denied->requestId);
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'auth_req_id' => $denied->authReqId,
    ])->assertJsonPath('error', 'access_denied');

    $expired = $ciba->request($registered->client, ['openid'], $user->id);
    BackchannelAuthRequest::query()->whereKey($expired->requestId)->update(['expires_at' => now()->subMinute()]);
    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'auth_req_id' => $expired->authReqId,
    ])->assertJsonPath('error', 'expired_token');
});

it('mints a token only once per auth_req_id (single-use)', function (): void {
    $registered = $this->makeClient(['openid']);
    $user = $this->makeUser('erin@example.test');
    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->approve($result->requestId);

    $poll = fn () => $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ]);

    $poll()->assertOk(); // first exchange succeeds

    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    // A second exchange with the same (leaked/observed) auth_req_id is refused.
    $poll()->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects an unknown auth_req_id', function (): void {
    $registered = $this->makeClient(['openid']);

    $this->postJson('/oauth/token', [
        'grant_type' => CIBA_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'auth_req_id' => 'auth_req_nope',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects a login_hint that resolves to no user', function (): void {
    $registered = $this->makeClient(['openid']);

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
        'login_hint' => 'ghost@example.test',
    ])->assertStatus(400)->assertJsonPath('error', 'unknown_user_id');
});

it('rejects a backchannel request with no login_hint', function (): void {
    $registered = $this->makeClient(['openid']);

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_request');
});

it('rejects an unauthenticated backchannel request', function (): void {
    $user = $this->makeUser('frank@example.test');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => 'nope',
        'login_hint' => $user->id,
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('advertises the CIBA endpoint, delivery mode and grant type in metadata', function (): void {
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('backchannel_authentication_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/backchannel_authentication'))
        ->assertJsonPath('backchannel_token_delivery_modes_supported', ['poll'])
        ->assertJsonFragment(['grant_types_supported' => [
            'authorization_code', 'client_credentials', 'refresh_token',
            'urn:ietf:params:oauth:grant-type:device_code', CIBA_GRANT,
        ]]);
});
