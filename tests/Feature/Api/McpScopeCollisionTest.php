<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Exceptions\InvalidApiDefinition;
use Cbox\Id\OAuthServer\Models\Api;
use Cbox\Id\OAuthServer\Models\ApiScope;
use Cbox\Id\OAuthServer\Support\SelfRegisteredScopes;
use Cbox\Id\OAuthServer\ValueObjects\ApiScopeDefinition;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * A registered API's scope keys and a host-declared resource's share one namespace: a
 * token request names a scope by key alone. A key both claim must never let a client that
 * registered itself for the declared resource reach the registered API.
 */

beforeEach(function (): void {
    User::query()->create(['id' => 'alice', 'email' => 'alice@tokens.test', 'status' => UserStatus::Active]);
    $this->declareProtectedResource('/mcp', ['mcp:tools', 'users:read']);
    config(['cbox-id.oauth.dynamic_registration.mode' => 'mcp']);
});

/** An API that owns `users:read`, written around the registry as a row from before the refusal. */
function collidingApi(): Api
{
    $api = Api::query()->create(['identifier' => 'https://orders.example.test', 'name' => 'Orders']);
    (new ApiScope(['environment_id' => $api->environment_id, 'api_id' => $api->id, 'key' => 'users:read']))
        ->forceFill(['tenant_requestable' => true])->save();

    return $api;
}

it('refuses an API scope a declared resource already accepts, and a reserved one', function (string $key): void {
    $this->declareProtectedResource('/vault', ['vault.lease']);

    expect(fn () => $this->makeApi('https://orders.example.test', [$key]))
        ->toThrow(InvalidApiDefinition::class)
        ->and(app(Apis::class)->identifiedBy('https://orders.example.test'))->toBeNull();

    $api = $this->makeApi('https://orders.example.test', ['orders:read']);

    expect(fn () => app(Apis::class)->defineScope($api, new ApiScopeDefinition($key)))
        ->toThrow(InvalidApiDefinition::class);
})->with(['users:read', 'mcp:tools', 'vault.manage', 'vault.lease']);

it('never hands a self-registered client a key a registered API owns', function (): void {
    collidingApi();

    $registered = $this->postJson('/oauth/register', [
        'client_name' => 'Anon',
        'redirect_uris' => ['http://127.0.0.1:40001/cb'],
        'scope' => 'users:read mcp:tools',
    ])->assertStatus(201);

    expect($registered->json('scope'))->toBe('mcp:tools')
        ->and(app(SelfRegisteredScopes::class)->narrow(['users:read', 'mcp:tools'], false))->toBe(['mcp:tools'])
        ->and(app(SelfRegisteredScopes::class)->defaults(false))->not->toContain('users:read');
});

it('never audiences a self-registered client\'s token to the registered API', function (): void {
    collidingApi();

    $registered = $this->postJson('/oauth/register', [
        'client_name' => 'Anon',
        'redirect_uris' => ['http://127.0.0.1:40001/cb'],
        'scope' => 'mcp:tools',
    ])->assertStatus(201);
    $clientId = (string) $registered->json('client_id');

    // A row that came to hold the key anyway: the token endpoint is the second wall.
    DB::table('oauth_clients')->where('client_id', $clientId)->update(['scopes' => json_encode(['users:read', 'mcp:tools'])]);

    $verifier = str_repeat('v', 50);
    $code = app(AuthorizationCodes::class)->issue(
        $clientId, 'alice', null, 'http://127.0.0.1:40001/cb', ['users:read'],
        Base64Url::encode(hash('sha256', $verifier, true)),
    );

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'http://127.0.0.1:40001/cb',
        'code_verifier' => $verifier,
    ]);

    if ($response->status() === 200) {
        $claims = (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', (string) $response->json('access_token'))[1]), true);

        expect($claims['aud'])->not->toContain('https://orders.example.test')
            ->and((array) $claims['aud'])->not->toContain('https://orders.example.test');
    } else {
        expect($response->status())->toBe(400);
    }
});
