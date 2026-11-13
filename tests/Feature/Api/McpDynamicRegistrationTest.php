<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Maintenance\Enums\PrunableTable;
use Cbox\Id\Maintenance\Pruner;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

// Token grants belong to existing, active subjects.
beforeEach(function (): void {
    User::query()->create(['id' => 'alice', 'email' => 'alice@tokens.test', 'status' => UserStatus::Active]);
});

/*
 * RFC 7591 registration in `mcp` mode: open, but only public clients, only the code flow,
 * only https/loopback redirects, only the scopes of resources that accept self-registered
 * clients — plus the per-address hourly ceiling and the sweep of registrations nobody uses.
 */

function mcpDcr(): void
{
    config(['cbox-id.oauth.dynamic_registration.mode' => 'mcp']);
}

function mcpResource(): string
{
    return rtrim(app(IssuerResolver::class)->issuer(), '/').'/mcp';
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function mcpRegistration(array $overrides = []): array
{
    return array_merge([
        'client_name' => 'MCP Inspector',
        'redirect_uris' => ['http://127.0.0.1:6274/oauth/callback'],
    ], $overrides);
}

beforeEach(function (): void {
    $this->declareProtectedResource('/mcp', ['mcp:tools', 'mcp:admin']);
    $this->declareProtectedResource('/internal', ['internal:ops'], dynamicClients: false);
});

it('registers a public client with the MCP defaults and advertises the endpoint', function (): void {
    mcpDcr();

    $response = $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);

    expect($response->json('token_endpoint_auth_method'))->toBe('none')
        ->and($response->json('client_secret'))->toBeNull()
        ->and($response->json('grant_types'))->toBe(['authorization_code', 'refresh_token'])
        // Open resources, allowed OIDC identity scopes, and offline_access for refresh.
        // Never the closed resource's scope or the other identity extensions.
        ->and(explode(' ', (string) $response->json('scope')))->toEqualCanonicalizing(['mcp:tools', 'mcp:admin', 'openid', 'profile', 'email', 'offline_access']);

    $this->getJson('/.well-known/oauth-authorization-server')->assertJsonPath('registration_endpoint', app(IssuerResolver::class)->issuer().'/oauth/register');
});

it('narrows requested scopes to open resources and allowed protocol scopes, never a reserved one', function (): void {
    mcpDcr();
    $this->makeApi('https://tax.example.test', ['tax:read']);

    $response = $this->postJson('/oauth/register', mcpRegistration([
        'scope' => 'mcp:tools internal:ops vault.manage vault.lease tax:read openid offline_access free:text',
    ]))->assertStatus(201);

    expect(explode(' ', (string) $response->json('scope')))->toBe(['mcp:tools', 'openid', 'offline_access']);
});

it('refuses a reserved scope even when a resource claims it is open', function (): void {
    mcpDcr();
    $this->declareProtectedResource('/vault', ['vault.lease']);

    $response = $this->postJson('/oauth/register', mcpRegistration(['scope' => 'vault.lease mcp:tools']))->assertStatus(201);

    expect($response->json('scope'))->toBe('mcp:tools');
});

it('refuses anything but a public client', function (string $method): void {
    mcpDcr();

    $this->postJson('/oauth/register', mcpRegistration(['token_endpoint_auth_method' => $method]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');

    expect(Client::query()->count())->toBe(0);
})->with(['client_secret_basic', 'client_secret_post', 'private_key_jwt']);

it('refuses grants beyond the code flow and its refresh', function (array $grants): void {
    mcpDcr();

    $this->postJson('/oauth/register', mcpRegistration(['grant_types' => $grants]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
})->with([
    'client_credentials' => [['authorization_code', 'client_credentials']],
    'device' => [['urn:ietf:params:oauth:grant-type:device_code']],
    'refresh alone' => [['refresh_token']],
]);

it('refuses redirect URIs that are not https or loopback', function (string $uri): void {
    mcpDcr();

    $this->postJson('/oauth/register', mcpRegistration(['redirect_uris' => [$uri]]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_redirect_uri');
})->with([
    'plain http' => 'http://client.example.test/cb',
    'custom scheme' => 'com.example.app:/cb',
    'fragment' => 'https://client.example.test/cb#x',
]);

it('accepts https and every loopback form', function (): void {
    mcpDcr();

    $this->postJson('/oauth/register', mcpRegistration(['redirect_uris' => [
        'https://client.example.test/cb',
        'http://localhost:3000/cb',
        'http://127.0.0.1/cb',
        'http://[::1]:8080/cb',
    ]]))->assertStatus(201);
});

it('refuses a back-channel logout URI', function (): void {
    mcpDcr();

    $this->postJson('/oauth/register', mcpRegistration(['backchannel_logout_uri' => 'https://client.example.test/logout']))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('lets the registered client complete the code flow to the open resource only', function (): void {
    mcpDcr();
    $registered = $this->postJson('/oauth/register', mcpRegistration(['redirect_uris' => ['https://app.test/cb']]))->assertStatus(201);
    $clientId = (string) $registered->json('client_id');

    $verifier = str_repeat('m', 50);
    $issue = fn (string $resource): string => app(AuthorizationCodes::class)->issue(
        $clientId, 'alice', null, 'https://app.test/cb', ['mcp:tools', 'offline_access'],
        Base64Url::encode(hash('sha256', $verifier, true)), resource: $resource,
    );

    $token = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $issue(mcpResource()),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ])->assertOk();

    $claims = (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', (string) $token->json('access_token'))[1]), true);
    expect($claims['aud'])->toBe(mcpResource());

    // The closed resource, and an arbitrary one, are refused at redemption.
    foreach ([rtrim(app(IssuerResolver::class)->issuer(), '/').'/internal', 'https://bank.example.test/'] as $resource) {
        $this->postJson('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $clientId,
            'code' => $issue($resource),
            'redirect_uri' => 'https://app.test/cb',
            'code_verifier' => $verifier,
        ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
    }
});

it('applies the MCP rules to an RFC 7592 update too', function (): void {
    mcpDcr();
    $registered = $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);

    $this->withToken((string) $registered->json('registration_access_token'))
        ->putJson('/oauth/register/'.$registered->json('client_id'), mcpRegistration([
            'client_id' => $registered->json('client_id'),
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]))
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_client_metadata');
});

it('holds an RFC 7592 update to the profile the client registered under, whatever the mode is now', function (string $mode): void {
    mcpDcr();
    $registered = $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);
    $clientId = (string) $registered->json('client_id');
    $before = Client::query()->where('client_id', $clientId)->firstOrFail()->only(['type', 'grant_types', 'token_endpoint_auth_method', 'redirect_uris']);

    config([
        'cbox-id.oauth.dynamic_registration.mode' => $mode,
        'cbox-id.oauth.dynamic_registration.initial_access_token' => 'iat-secret',
    ]);

    $bodies = [
        mcpRegistration(['token_endpoint_auth_method' => 'client_secret_post', 'grant_types' => ['authorization_code', 'client_credentials', 'urn:openid:params:grant-type:ciba']]),
        mcpRegistration(['grant_types' => ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code']]),
        mcpRegistration(['redirect_uris' => ['com.example.app:/cb']]),
    ];

    foreach ($bodies as $body) {
        $response = $this->withToken((string) $registered->json('registration_access_token'))
            ->putJson('/oauth/register/'.$clientId, $body);

        expect($response->status())->toBeIn([400, 403])
            ->and($response->json('client_secret'))->toBeNull();
    }

    expect(Client::query()->where('client_id', $clientId)->firstOrFail()->only(['type', 'grant_types', 'token_endpoint_auth_method', 'redirect_uris']))->toBe($before);
})->with(['disabled', 'protected', 'open']);

it('refuses to read or update a registration while registration is disabled, and still lets the client delete itself', function (): void {
    mcpDcr();
    $registered = $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);
    $clientId = (string) $registered->json('client_id');
    $token = (string) $registered->json('registration_access_token');

    config(['cbox-id.oauth.dynamic_registration.mode' => 'disabled']);

    $this->withToken($token)->getJson('/oauth/register/'.$clientId)->assertStatus(403)->assertJsonPath('error', 'access_denied');
    $this->withToken($token)->putJson('/oauth/register/'.$clientId, mcpRegistration(['client_name' => 'Renamed']))->assertStatus(403);
    $this->withToken($token)->deleteJson('/oauth/register/'.$clientId)->assertStatus(204);

    expect(Client::query()->where('client_id', $clientId)->exists())->toBeFalse();
});

it('records the profile a client registered under', function (): void {
    mcpDcr();
    $mcp = $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);

    config(['cbox-id.oauth.dynamic_registration.mode' => 'open']);
    $open = $this->postJson('/oauth/register', mcpRegistration(['token_endpoint_auth_method' => 'client_secret_basic']))->assertStatus(201);

    expect(Client::query()->where('client_id', $mcp->json('client_id'))->value('registration_profile'))->toBe('mcp')
        ->and(Client::query()->where('client_id', $open->json('client_id'))->value('registration_profile'))->toBe('general');
});

// ---------------------------------------------------------------------------------------
// Throttle.
// ---------------------------------------------------------------------------------------

it('holds unauthenticated registration to a per-address hourly ceiling', function (): void {
    mcpDcr();
    config(['cbox-id.oauth.dynamic_registration.max_per_ip_per_hour' => 2]);

    $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);
    $this->postJson('/oauth/register', mcpRegistration())->assertStatus(201);
    $this->postJson('/oauth/register', mcpRegistration())->assertStatus(429);

    // Another address is not affected.
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])
        ->postJson('/oauth/register', mcpRegistration())->assertStatus(201);
});

it('does not apply the hourly ceiling to protected registration', function (): void {
    config([
        'cbox-id.oauth.dynamic_registration.mode' => 'protected',
        'cbox-id.oauth.dynamic_registration.initial_access_token' => 'iat-secret',
        'cbox-id.oauth.dynamic_registration.max_per_ip_per_hour' => 1,
    ]);

    foreach (range(1, 3) as $ignored) {
        $this->withToken('iat-secret')->postJson('/oauth/register', mcpRegistration(['token_endpoint_auth_method' => 'none']))->assertStatus(201);
    }
});

// ---------------------------------------------------------------------------------------
// Pruning unused registrations.
// ---------------------------------------------------------------------------------------

it('stamps last_used_at when a token is minted, at most once an hour', function (): void {
    $client = $this->makeClient(['api.read']);
    $issuer = app(TokenIssuer::class);

    $issuer->issueClientCredentials($client->client, ['api.read']);
    $first = $client->client->fresh()?->last_used_at;
    expect($first)->not->toBeNull();

    $this->travel(10)->minutes();
    $issuer->issueClientCredentials($client->client, ['api.read']);
    expect($client->client->fresh()?->last_used_at?->equalTo($first))->toBeTrue();

    $this->travel(2)->hours();
    $issuer->issueClientCredentials($client->client, ['api.read']);
    expect($client->client->fresh()?->last_used_at?->greaterThan($first))->toBeTrue();
});

it('prunes self-registered clients nobody used in the window, and nothing else', function (): void {
    mcpDcr();
    config(['cbox-id.prune.retention_days.oauth_clients' => 30]);

    $abandoned = (string) $this->postJson('/oauth/register', mcpRegistration())->json('client_id');
    $neverUsedButNew = null;
    $usedRecently = (string) $this->postJson('/oauth/register', mcpRegistration())->json('client_id');
    $holdsAGrant = (string) $this->postJson('/oauth/register', mcpRegistration())->json('client_id');
    $operator = $this->makeClient(['api.read'])->client->client_id;

    $this->travel(40)->days();

    $neverUsedButNew = (string) $this->postJson('/oauth/register', mcpRegistration())->json('client_id');
    DB::table('oauth_clients')->where('client_id', $usedRecently)->update(['last_used_at' => now()->subDays(2)]);
    RefreshToken::query()->create([
        'family_id' => 'fam',
        'client_id' => $holdsAGrant,
        'user_id' => 'alice',
        'token_hash' => hash('sha256', 'rt'),
        'scopes' => ['mcp:tools'],
        'expires_at' => now()->addDays(5),
    ]);

    $outcome = app(Pruner::class)->prune(PrunableTable::OauthClients);

    $remaining = DB::table('oauth_clients')->pluck('client_id')->all();

    expect($outcome->deleted)->toBe(1)
        ->and($remaining)->not->toContain($abandoned)
        ->and($remaining)->toContain($neverUsedButNew, $usedRecently, $holdsAGrant, $operator);
});

it('does not prune clients unless the operator opted in', function (): void {
    expect(config('cbox-id.prune.retention_days.oauth_clients'))->toBeNull()
        ->and(app(Pruner::class)->prune(PrunableTable::OauthClients)->deleted)->toBe(0);
});
