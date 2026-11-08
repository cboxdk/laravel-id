<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\RateLimiter;

uses(RefreshDatabase::class);

/*
|--------------------------------------------------------------------------
| CIBA and the device grant for self-registered agents and CLIs.
|--------------------------------------------------------------------------
|
| A protected resource opens the decoupled grants to self-registered clients
| (`dynamic_client_grants`); such a client registers with its own key (or, where the
| resource allows it, as a public client), names the resource on every request, sends a
| binding message the person can match, and gets a token bound to that resource.
*/

function agentIssuer(): string
{
    return rtrim(app(IssuerResolver::class)->issuer(), '/');
}

function agentResource(): string
{
    return agentIssuer().'/brain';
}

/** @return array{pem: string, jwk: array<string, string>, kid: string} */
function agentKey(): array
{
    $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    openssl_pkey_export($key, $pem);
    $details = openssl_pkey_get_details($key);
    $b64 = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

    return [
        'pem' => (string) $pem,
        'kid' => 'agent-1',
        'jwk' => ['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'agent-1', 'n' => $b64($details['rsa']['n']), 'e' => $b64($details['rsa']['e'])],
    ];
}

/** @param array{pem: string, kid: string} $key */
function agentAssertion(string $clientId, array $key): string
{
    return JWT::encode([
        'iss' => $clientId,
        'sub' => $clientId,
        'aud' => agentIssuer().'/oauth/token',
        'jti' => bin2hex(random_bytes(16)),
        'iat' => time(),
        'exp' => time() + 60,
    ], $key['pem'], 'RS256', $key['kid']);
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function agentRegister(array $overrides = []): array
{
    return test()->postJson('/oauth/register', array_merge([
        'client_name' => 'Brain CLI',
        'grant_types' => ['urn:openid:params:grant-type:ciba', 'refresh_token'],
        'scope' => 'openid brain:read',
    ], $overrides))->assertCreated()->json();
}

/** @param array{pem: string, kid: string} $key */
function agentAuth(string $clientId, array $key): array
{
    return [
        'client_id' => $clientId,
        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion' => agentAssertion($clientId, $key),
    ];
}

function agentPerson(string $email = 'alex@acme.test'): string
{
    $subject = app(Subjects::class)->create($email, 'Alex');
    app(Subjects::class)->markEmailVerified($subject->id, $email);

    return $subject->id;
}

/** @return array<string, mixed> */
function agentClaims(string $jwt): array
{
    return json_decode(base64_decode(strtr(explode('.', $jwt)[1], '-_', '+/')), true);
}

beforeEach(function (): void {
    config(['cbox-id.oauth.dynamic_registration.mode' => 'mcp']);
    config(['cbox-id.oauth.protected_resources' => [[
        'path' => '/brain',
        'scopes' => ['brain:read', 'brain:write'],
        'dynamic_clients' => true,
        'dynamic_client_grants' => ['ciba', 'device_code'],
    ], [
        'path' => '/closed',
        'scopes' => ['closed:read'],
        'dynamic_clients' => true,
    ]]]);
    RateLimiter::clear('x');
});

it('registers a self-registered client with its own key and the ciba grant, no redirect needed', function (): void {
    $key = agentKey();

    $registered = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]]);

    expect($registered['token_endpoint_auth_method'])->toBe('private_key_jwt')
        ->and($registered['grant_types'])->toContain('urn:openid:params:grant-type:ciba')
        ->and($registered)->not->toHaveKey('client_secret');
});

it('refuses ciba at registration when no resource opened it', function (): void {
    config(['cbox-id.oauth.protected_resources' => [['path' => '/closed', 'scopes' => ['closed:read'], 'dynamic_clients' => true]]]);
    $key = agentKey();

    $this->postJson('/oauth/register', [
        'client_name' => 'Brain CLI',
        'token_endpoint_auth_method' => 'private_key_jwt',
        'jwks' => ['keys' => [$key['jwk']]],
        'grant_types' => ['urn:openid:params:grant-type:ciba'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');
})->group('security');

it('refuses a public client the ciba grant unless a resource allows public backchannel', function (): void {
    $this->postJson('/oauth/register', [
        'client_name' => 'Brain CLI',
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['urn:openid:params:grant-type:ciba'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_client_metadata');
})->group('security');

it('signs a person in with CIBA, bound to the resource the request named', function (): void {
    $key = agentKey();
    $client = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]])['client_id'];
    $person = agentPerson();

    $started = $this->postJson('/oauth/backchannel_authentication', [
        ...agentAuth($client, $key),
        'login_hint' => $person,
        'scope' => 'openid brain:read',
        'binding_message' => 'Brain CLI on laptop · 4F2K',
        'resource' => agentResource(),
    ])->assertOk();

    $request = BackchannelAuthRequest::query()->where('user_id', $person)->sole();
    expect($request->resource)->toBe(agentResource())
        ->and($request->binding_message)->toBe('Brain CLI on laptop · 4F2K');

    app(BackchannelAuthentication::class)->approve($request->id, $person);

    $token = $this->postJson('/oauth/token', [
        ...agentAuth($client, $key),
        'grant_type' => 'urn:openid:params:grant-type:ciba',
        'auth_req_id' => $started->json('auth_req_id'),
    ])->assertOk();

    $claims = agentClaims($token->json('access_token'));
    expect((array) $claims['aud'])->toContain(agentResource())
        ->and($claims['sub'])->toBe($person)
        ->and(explode(' ', (string) ($claims['scope'] ?? '')))->toContain('brain:read');
});

it('refuses a poll that names another resource than the request', function (): void {
    $key = agentKey();
    $client = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]])['client_id'];
    $person = agentPerson();

    $started = $this->postJson('/oauth/backchannel_authentication', [
        ...agentAuth($client, $key), 'login_hint' => $person, 'scope' => 'openid brain:read',
        'binding_message' => 'Brain · 7Q1P', 'resource' => agentResource(),
    ])->assertOk();
    app(BackchannelAuthentication::class)->approve(BackchannelAuthRequest::query()->sole()->id, $person);

    $this->postJson('/oauth/token', [
        ...agentAuth($client, $key), 'grant_type' => 'urn:openid:params:grant-type:ciba',
        'auth_req_id' => $started->json('auth_req_id'), 'resource' => agentIssuer().'/closed',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
})->group('security');

it('requires a self-registered client to name a resource that opened ciba, and a binding message', function (): void {
    $key = agentKey();
    $client = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]])['client_id'];
    $person = agentPerson();
    $base = ['login_hint' => $person, 'scope' => 'openid', 'binding_message' => 'Brain · 1A2B'];

    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_target');

    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base, 'resource' => agentIssuer().'/closed'])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_target');

    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), 'login_hint' => $person, 'scope' => 'openid', 'resource' => agentResource()])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_binding_message');

    expect(BackchannelAuthRequest::query()->count())->toBe(0);
})->group('security');

it('lets a public client use ciba where the resource allows it, held to the same rules', function (): void {
    config(['cbox-id.oauth.protected_resources.0.dynamic_public_backchannel' => true]);
    $client = agentRegister(['token_endpoint_auth_method' => 'none'])['client_id'];
    $person = agentPerson();

    $this->postJson('/oauth/backchannel_authentication', ['client_id' => $client, 'login_hint' => $person, 'scope' => 'openid', 'resource' => agentResource()])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_binding_message');

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $client, 'login_hint' => $person, 'scope' => 'openid',
        'binding_message' => 'Brain · 9X8Y', 'resource' => agentResource(),
    ])->assertOk()->assertJsonStructure(['auth_req_id', 'expires_in', 'interval']);
})->group('security');

it('never lets an operator-registered public client start ciba', function (): void {
    $registered = $this->makeClient(['openid'], ClientType::Public, ['urn:openid:params:grant-type:ciba']);
    agentPerson();

    $this->postJson('/oauth/backchannel_authentication', [
        'client_id' => $registered->client->client_id, 'login_hint' => 'alex@acme.test', 'binding_message' => 'x',
    ])->assertStatus(401)->assertJsonPath('error', 'invalid_client');
})->group('security');

it('accepts a user id or a confirmed email as login_hint, never an unconfirmed one', function (): void {
    $key = agentKey();
    $client = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]])['client_id'];
    $base = ['scope' => 'openid', 'binding_message' => 'Brain · 2C3D', 'resource' => agentResource()];
    $unconfirmed = app(Subjects::class)->create('new@acme.test', 'New')->id;

    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base, 'login_hint' => 'new@acme.test'])
        ->assertStatus(400)->assertJsonPath('error', 'unknown_user_id');
    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base, 'login_hint' => $unconfirmed])
        ->assertOk();
    agentPerson('ok@acme.test');
    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base, 'login_hint' => 'ok@acme.test'])
        ->assertOk();
})->group('security');

it('rate limits a client hammering one person, and caps prompts per person across clients', function (): void {
    $key = agentKey();
    $client = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]])['client_id'];
    $person = agentPerson();
    $base = ['login_hint' => $person, 'scope' => 'openid', 'binding_message' => 'Brain · 5E6F', 'resource' => agentResource()];
    config(['cbox-id.oauth.ciba.rate_limits.per_client_hint' => 2, 'cbox-id.oauth.ciba.rate_limits.per_person' => 3]);

    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base])->assertOk();
    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base])->assertOk();
    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($client, $key), ...$base])
        ->assertStatus(429)->assertJsonPath('error', 'slow_down')->assertHeader('Retry-After');

    $otherKey = agentKey();
    $other = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$otherKey['jwk']]]])['client_id'];
    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($other, $otherKey), ...$base])->assertOk();
    $this->postJson('/oauth/backchannel_authentication', [...agentAuth($other, $otherKey), ...$base])
        ->assertStatus(429)->assertJsonPath('error', 'slow_down');

    expect(BackchannelAuthRequest::query()->count())->toBe(3);
})->group('security');

it('audits every request and decision', function (): void {
    $key = agentKey();
    $client = agentRegister(['token_endpoint_auth_method' => 'private_key_jwt', 'jwks' => ['keys' => [$key['jwk']]]])['client_id'];
    $person = agentPerson();

    $this->postJson('/oauth/backchannel_authentication', [
        ...agentAuth($client, $key), 'login_hint' => $person, 'scope' => 'openid',
        'binding_message' => 'Brain · 3G4H', 'resource' => agentResource(),
    ])->assertOk();
    app(BackchannelAuthentication::class)->deny(BackchannelAuthRequest::query()->sole()->id, $person);

    expect(AuditEntry::query()->where('action', 'oauth.ciba.requested')->where('actor_id', $client)->exists())->toBeTrue()
        ->and(AuditEntry::query()->where('action', 'oauth.ciba.denied')->where('actor_id', $person)->exists())->toBeTrue();
});

it('lets a self-registered client use the device grant for a resource that opened it', function (): void {
    $client = agentRegister([
        'token_endpoint_auth_method' => 'none',
        'grant_types' => ['urn:ietf:params:oauth:grant-type:device_code'],
    ])['client_id'];

    $this->postJson('/oauth/device_authorization', ['client_id' => $client, 'scope' => 'openid'])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_target');
    $this->postJson('/oauth/device_authorization', ['client_id' => $client, 'scope' => 'openid', 'resource' => agentIssuer().'/closed'])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_target');
    $this->postJson('/oauth/device_authorization', ['client_id' => $client, 'scope' => 'openid', 'resource' => agentResource()])
        ->assertOk()->assertJsonStructure(['device_code', 'user_code', 'verification_uri']);
});
