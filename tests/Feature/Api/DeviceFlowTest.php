<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

it('starts a device grant with a user_code and verification URI', function (): void {
    $registered = $this->makeClient(['openid', 'profile'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $response = $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid profile',
    ]);

    $response->assertOk()->assertJsonStructure([
        'device_code', 'user_code', 'verification_uri', 'verification_uri_complete', 'expires_in', 'interval',
    ]);

    expect($response->json('device_code'))->toStartWith('dvc_')
        ->and($response->json('user_code'))->toMatch('/^[A-Z]{4}-[A-Z]{4}$/')
        ->and($response->json('verification_uri'))->toEndWith('/device');
});

it('rejects a confidential client that presents no secret', function (): void {
    // A confidential client must authenticate at the device endpoint — otherwise
    // anyone knowing its client_id could start flows (and push approval prompts at
    // users) under its identity (RFC 8628 §3.1).
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'scope' => 'openid',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('rejects a confidential client that presents a wrong secret', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'client_secret' => 'not-the-secret',
        'scope' => 'openid',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
});

it('accepts a confidential client with the correct secret', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid',
    ])->assertOk()->assertJsonStructure(['device_code', 'user_code']);
});

it('accepts a public client by client_id alone', function (): void {
    // Public clients (TVs, CLIs) hold no secret — client_id is all they can present,
    // and that is enough for them.
    $registered = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'scope' => 'openid',
    ])->assertOk()->assertJsonStructure(['device_code', 'user_code']);
});

it('resolves a live request by user_code for the verification screen (never the device_code)', function (): void {
    $registered = $this->makeClient(['openid', 'profile'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid', 'profile']);

    // The verification screen looks the code up (case-insensitively) to show what is asking.
    $pending = $device->pending(strtolower($result->userCode));

    expect($pending)->not->toBeNull()
        ->and($pending->clientId)->toBe($registered->client->client_id)
        ->and($pending->scopes)->toBe(['openid', 'profile'])
        // The VO carries no device_code — the requesting device's polling secret stays secret.
        ->and(json_encode($pending))->not->toContain($result->deviceCode);

    // Unknown, approved and expired codes all resolve to null (nothing to consent to).
    expect($device->pending('ZZZZ-ZZZZ'))->toBeNull();
    $device->approve($result->userCode, 'user-1', 'org-1');
    expect($device->pending($result->userCode))->toBeNull();
});

it('polls pending, then issues a token once the user approves', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid']);

    // While unapproved, the token endpoint answers authorization_pending.
    $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ])->assertStatus(400)->assertJsonPath('error', 'authorization_pending');

    // The user approves at the verification URI (binding their identity).
    expect($device->approve($result->userCode, 'user-1', 'org-1'))->toBeTrue();

    // Skip the polling interval so the next poll isn't slow_down'd.
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $token = $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ])->assertOk()->json('access_token');

    $introspection = app(TokenIntrospector::class)->introspect($token);
    expect($introspection->active)->toBeTrue()
        ->and($introspection->subject)->toBe('user-1');
});

it('returns slow_down when polling faster than the interval', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $result = app(DeviceAuthorization::class)->request($registered->client, ['openid']);

    $poll = fn () => $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ]);

    $poll()->assertJsonPath('error', 'authorization_pending'); // first poll allowed
    $poll()->assertJsonPath('error', 'slow_down');             // immediate re-poll throttled
});

it('reports denial and expiry', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $device = app(DeviceAuthorization::class);

    $denied = $device->request($registered->client, ['openid']);
    $device->deny($denied->userCode);
    $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'device_code' => $denied->deviceCode,
    ])->assertJsonPath('error', 'access_denied');

    $expired = $device->request($registered->client, ['openid']);
    DeviceCode::query()->where('user_code', $expired->userCode)->update(['expires_at' => now()->subMinute()]);
    $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'device_code' => $expired->deviceCode,
    ])->assertJsonPath('error', 'expired_token');
});

it('mints a token only once per device_code (single-use)', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid']);
    $device->approve($result->userCode, 'user-1', null);

    $poll = fn () => $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ]);

    $poll()->assertOk(); // first exchange succeeds

    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    // A second exchange with the same (leaked/observed) code is refused.
    $poll()->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('rejects an unknown device_code', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT, 'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret, 'device_code' => 'dvc_nope',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('advertises the device endpoint and grant type in metadata', function (): void {
    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('device_authorization_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/device_authorization'))
        ->assertJsonFragment(['grant_types_supported' => [
            'authorization_code', 'client_credentials', 'refresh_token', DEVICE_GRANT,
            'urn:openid:params:grant-type:ciba',
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ]]);
});
