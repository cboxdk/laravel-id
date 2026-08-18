<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGranted;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

/*
 * THE CLIENT'S REGISTERED SCOPES ARE A CEILING FOR EVERY TOKEN, not just the access token.
 *
 * The access token has always been filtered — JwtTokenIssuer::grantScopes() drops anything
 * the client is not registered for. The device and CIBA grants stored the REQUESTED scopes
 * verbatim, and the token endpoint then read those raw scopes to decide whether to issue a
 * refresh token and what to put in it.
 *
 * So a client registered for `openid` alone could ask a device grant for
 * `openid offline_access`, receive a correctly downscoped access token — and a refresh
 * token anyway, carrying a scope it was never granted. That refresh token rotates
 * indefinitely: long-lived access the registration explicitly withheld, obtained by
 * asking for it in the one place nothing was checking.
 */
function approvedDeviceGrant(array $registeredScopes, string $requestedScope): array
{
    $registered = test()->makeClient($registeredScopes, grantTypes: [DEVICE_GRANT_TYPE]);

    $start = test()->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => $requestedScope,
    ])->assertOk();

    app(DeviceAuthorization::class)->approve($start->json('user_code'), 'user-1', null);

    $token = test()->postJson('/oauth/token', [
        'grant_type' => DEVICE_GRANT_TYPE,
        'device_code' => $start->json('device_code'),
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
    ]);

    return [$registered, $token];
}

it('refuses a device grant that asks for a scope the client does not hold', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: [DEVICE_GRANT_TYPE]);

    $this->postJson('/oauth/device_authorization', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'scope' => 'openid offline_access',
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');

    // And nothing was created: a refused request must not leave a pending grant behind
    // for the same over-broad scopes to be polled out of later.
    expect(DeviceCode::query()->count())->toBe(0);
})->group('security');

it('never lets a stored grant carry a scope the client does not hold', function (): void {
    // The property underneath the refusal, asserted where it actually lives. Even if a
    // future caller reaches the service directly rather than through the endpoint, the
    // grant cannot come into existence holding `offline_access` — which is what the token
    // endpoint reads to decide on a refresh token.
    $registered = $this->makeClient(['openid'], grantTypes: [DEVICE_GRANT_TYPE]);

    expect(fn () => app(DeviceAuthorization::class)->request($registered->client, ['openid', 'offline_access']))
        ->toThrow(ScopeNotGranted::class);
})->group('security');

it('still issues both to a client that holds the scopes', function (): void {
    // The positive control: a ceiling that refuses everything passes both tests above.
    [, $token] = approvedDeviceGrant(['openid', 'offline_access'], 'openid offline_access');

    $token->assertOk();

    expect($token->json('refresh_token'))->toBeString()
        ->and($token->json('id_token'))->toBeString();
})->group('security');

/*
 * CIBA gets the same ceiling and the same refusal. Its grant feeds the same token endpoint
 * through the same `$grant->scopes`, so leaving it unfiltered would have left the hole
 * open on the other machine-initiated flow.
 */
it('refuses a CIBA request that asks for a scope the client does not hold', function (): void {
    $subject = app(Subjects::class)->create('ciba@acme.test', 'Ciba User');
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'login_hint' => $subject->email,
        'scope' => 'openid offline_access',
    ])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');
})->group('security');

it('still starts a CIBA request within the client’s registered scopes', function (): void {
    $subject = app(Subjects::class)->create('ciba-ok@acme.test', 'Ciba User');
    $registered = $this->makeClient(['openid', 'offline_access'], grantTypes: ['urn:openid:params:grant-type:ciba']);

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'login_hint' => $subject->email,
        'scope' => 'openid offline_access',
    ])->assertOk()->assertJsonStructure(['auth_req_id']);
})->group('security');
