<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

it('starts a device grant with a user_code and verification URI', function (): void {
    $registered = $this->makeClient(['openid', 'profile']);

    $response = $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'scope' => 'openid profile',
    ]);

    $response->assertOk()->assertJsonStructure([
        'device_code', 'user_code', 'verification_uri', 'verification_uri_complete', 'expires_in', 'interval',
    ]);

    expect($response->json('device_code'))->toStartWith('dvc_')
        ->and($response->json('user_code'))->toMatch('/^[A-Z]{4}-[A-Z]{4}$/')
        ->and($response->json('verification_uri'))->toEndWith('/device');
});

it('polls pending, then issues a token once the user approves', function (): void {
    $registered = $this->makeClient(['openid']);
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
    $registered = $this->makeClient(['openid']);
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
    $registered = $this->makeClient(['openid']);
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
    $registered = $this->makeClient(['openid']);
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
    $registered = $this->makeClient(['openid']);

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
        ]]);
});
