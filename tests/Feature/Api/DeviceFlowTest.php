<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\OAuthServer\Contracts\AuthenticationAwareDeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\GrantPollStatus;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationEvent;
use Cbox\Id\OAuthServer\ValueObjects\AuthenticationRequirement;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

// Token grants belong to existing, active subjects.
beforeEach(function (): void {
    User::query()->create(['id' => 'user-1', 'email' => 'user-1@tokens.test', 'status' => UserStatus::Active]);
});

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

    expect($response->json('device_code'))->toStartWith('cbid_dc_')
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
    config(['cbox-id.oauth.authorization_endpoint_path' => '/oauth/authorize']);

    $this->getJson('/.well-known/oauth-authorization-server')
        ->assertOk()
        ->assertJsonPath('device_authorization_endpoint', fn (string $v): bool => str_ends_with($v, '/oauth/device_authorization'))
        ->assertJsonFragment(['grant_types_supported' => [
            'authorization_code', 'client_credentials', 'refresh_token', DEVICE_GRANT,
            'urn:openid:params:grant-type:ciba',
            'urn:ietf:params:oauth:grant-type:token-exchange',
        ]]);
});

it('issues a refresh token when the device client asked for offline access', function (): void {
    // RFC 8628 exists for CLIs, TVs and headless devices — the clients with no
    // browser to bounce through when an access token expires. `offline_access` was
    // accepted at the device-authorization endpoint, stored on the grant, and then
    // dropped at redemption, so every one of them was signed out an hour later with
    // no way back but a fresh user_code.
    $registered = $this->makeClient(
        ['openid', 'offline_access'],
        grantTypes: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
    );
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid', 'offline_access']);

    expect($device->approve($result->userCode, 'user-1', 'org-1'))->toBeTrue();
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $body = $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ])->assertOk()->json();

    expect($body['refresh_token'] ?? null)->toBeString()
        // And an ID Token, as every other user-present grant returns: without one an
        // OIDC client learns nothing about WHO signed in but a bearer token.
        ->and($body['id_token'] ?? null)->toBeString();
});

it('issues no refresh token when offline access was not asked for', function (): void {
    // The scope is the request, not a default. A client that never asked for a
    // long-lived session must not silently be given one.
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid']);

    expect($device->approve($result->userCode, 'user-1', 'org-1'))->toBeTrue();
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $body = $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ])->assertOk()->json();

    expect($body)->not->toHaveKey('refresh_token');
});

it('issues no refresh token to a device client that may not redeem one', function (): void {
    // `offline_access` granted, but the registration never named `refresh_token`, so
    // the refresh grant would refuse this client with `unauthorized_client`. Minting a
    // long-lived credential its holder can never use is exposure for nothing.
    $registered = $this->makeClient(
        ['openid', 'offline_access'],
        grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
    );
    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid', 'offline_access']);

    expect($device->approve($result->userCode, 'user-1', 'org-1'))->toBeTrue();
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $body = $this->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ])->assertOk()->json();

    expect($body)->not->toHaveKey('refresh_token')
        ->and(RefreshToken::query()->count())->toBe(0);
})->group('security');

it('preserves only the recorded device authentication through issuance and refresh', function (?array $amr, ?string $acr, bool $satisfiesAal2): void {
    $registered = $this->makeClient(['openid', 'offline_access'], grantTypes: [DEVICE_GRANT, 'refresh_token']);
    $device = app(DeviceAuthorization::class);
    expect($device)->toBeInstanceOf(AuthenticationAwareDeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid', 'offline_access']);
    $authTime = $amr === null ? null : now()->subHour()->getTimestamp();

    // The three-argument contract still works, but cannot establish authentication.
    $approved = $amr === null
        ? $device->approve($result->userCode, 'user-1', null)
        : $device->approveAuthenticated($result->userCode, 'user-1', null, new AuthenticationEvent($authTime, $amr));
    expect($approved)->toBeTrue();

    // Re-approval must not replace the evidence, including upgrading a weak grant.
    expect($device->approveAuthenticated($result->userCode, 'user-1', null, new AuthenticationEvent(time(), ['passkey', 'mfa'])))->toBeFalse();

    $poll = [
        'grant_type' => DEVICE_GRANT,
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
        // Client-supplied claims are not authentication evidence.
        'acr' => 'urn:cbox-id:aal2', 'amr' => ['mfa'], 'auth_time' => time(),
    ];
    $response = $this->postJson('/oauth/token', $poll)->assertOk();

    for ($generation = 0; $generation < 3; $generation++) {
        $access = app(TokenIntrospector::class)->introspect($response->json('access_token'));
        $identity = app(TokenSigner::class)->verify($response->json('id_token'), [SigningAlg::RS256]);

        expect($access->active)->toBeTrue()
            ->and($access->claims['auth_time'] ?? null)->toBe($authTime)
            ->and($access->claims['acr'] ?? null)->toBe($acr)
            ->and($access->claims)->not->toHaveKey('amr')
            ->and($identity->get('auth_time'))->toBe($authTime)
            ->and($identity->get('acr'))->toBe($acr)
            ->and($identity->get('amr'))->toBe($amr === null || $amr === [] ? null : $amr)
            ->and(AuthenticationRequirement::of(AuthenticationContextClass::Aal2)->assessToken($access)->isSatisfied())->toBe($satisfiesAal2);

        if ($generation < 2) {
            $this->travel(1)->minutes();
            $response = $this->postJson('/oauth/token', [
                'grant_type' => 'refresh_token',
                'client_id' => $registered->client->client_id,
                'client_secret' => $registered->secret,
                'refresh_token' => $response->json('refresh_token'),
                'acr' => 'urn:cbox-id:aal2', 'amr' => ['mfa'], 'auth_time' => time(),
            ])->assertOk();
        }
    }

    $this->postJson('/oauth/token', $poll)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
})->with([
    'MFA' => [['pwd', 'otp'], 'urn:cbox-id:aal2', true],
    'password only' => [['pwd'], 'urn:cbox-id:aal1', false],
    'unknown methods' => [[], null, false],
    'legacy approval' => [null, null, false],
])->group('security');

it('adds nullable device evidence without upgrading an existing approval, and rolls back', function (): void {
    $migration = require __DIR__.'/../../../database/migrations/2026_11_27_000100_remember_device_grant_authentication.php';
    $migration->down();
    expect(Schema::hasColumn('device_codes', 'auth_time'))->toBeFalse()
        ->and(Schema::hasColumn('device_codes', 'amr'))->toBeFalse();

    $client = $this->makeClient(['openid'], grantTypes: [DEVICE_GRANT])->client;
    $device = app(DeviceAuthorization::class);
    $result = $device->request($client, ['openid']);
    DeviceCode::query()->where('user_code', $result->userCode)->update([
        'status' => GrantPollStatus::Approved, 'user_id' => 'user-1',
    ]);

    $migration->up();
    $grant = $device->redeem($client->client_id, $result->deviceCode);
    expect($grant->userId)->toBe('user-1')
        ->and($grant->authTime)->toBeNull()
        ->and($grant->amr)->toBe([]);
});
