<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\Models\PushedAuthorizationRequest;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\Support\ResourceParameter;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * RFC 8707 resource indicators for resources the HOST declares (an MCP endpoint at
 * `{issuer}/mcp`), driven through the token endpoint for every grant that takes one —
 * plus the refusals: several resources, a malformed one, an unknown one for a
 * self-registered client, and a refresh that tries to change audience.
 */

function riIssuer(): string
{
    return app(IssuerResolver::class)->issuer();
}

function riMcp(): string
{
    return rtrim(riIssuer(), '/').'/mcp';
}

/**
 * @return array<string, mixed>
 */
function riClaims(string $jwt): array
{
    return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
}

/**
 * Redeem a code minted the way the host's /authorize mints one — resource bound to it.
 *
 * @param  list<string>  $scopes
 * @param  array<string, string>  $extra
 */
function riCodeFlow(RegisteredClient|Client $client, array $scopes, ?string $resource, array $extra = [], ?string $secret = null): TestResponse
{
    $model = $client instanceof RegisteredClient ? $client->client : $client;
    $secret ??= $client instanceof RegisteredClient ? $client->secret : null;
    $verifier = str_repeat('v', 50);

    $code = app(AuthorizationCodes::class)->issue(
        $model->client_id,
        'alice',
        null,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', $verifier, true)),
        resource: $resource,
    );

    return test()->postJson('/oauth/token', array_filter([
        'grant_type' => 'authorization_code',
        'client_id' => $model->client_id,
        'client_secret' => $secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
        ...$extra,
    ], static fn (?string $value): bool => $value !== null));
}

/**
 * A client that registered itself (RFC 7591): the registration access token is the mark.
 *
 * @param  list<string>  $scopes
 */
function riSelfRegistered(array $scopes): RegisteredClient
{
    $registered = test()->makeClient($scopes, ClientType::Public, grantTypes: ['authorization_code', 'refresh_token']);
    $registered->client->forceFill(['registration_access_token_hash' => hash('sha256', 'reg')])->save();

    return $registered;
}

// ---------------------------------------------------------------------------------------
// authorization_code → token: the resource becomes `aud`.
// ---------------------------------------------------------------------------------------

it('audiences an authorization-code token to a declared resource and keeps only its scopes', function (): void {
    $this->declareProtectedResource(scopes: ['mcp:tools', 'mcp:admin']);
    $client = $this->makeClient(['openid', 'mcp:tools', 'legacy:x', 'offline_access'], grantTypes: ['authorization_code', 'refresh_token']);

    $response = riCodeFlow($client, ['openid', 'mcp:tools', 'legacy:x', 'offline_access'], riMcp())->assertOk();
    $claims = riClaims($response->json('access_token'));

    // `openid` is granted, so the issuer rides along as a second audience (UserInfo).
    expect($claims['aud'])->toBe([riMcp(), riIssuer()])
        ->and($claims['scope'])->toBe('openid mcp:tools offline_access')
        // RFC 6749 §5.1: the narrowed set is echoed.
        ->and($response->json('scope'))->toBe('openid mcp:tools offline_access');
});

it('audiences a token to the declared resource alone when no openid is granted', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], grantTypes: ['authorization_code']);

    $claims = riClaims(riCodeFlow($client, ['mcp:tools'], riMcp())->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe(riMcp())
        ->and($claims['scope'])->toBe('mcp:tools');
});

it('refuses a token request naming a different resource than the code was granted for', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], grantTypes: ['authorization_code']);

    riCodeFlow($client, ['mcp:tools'], riMcp(), ['resource' => 'https://elsewhere.example.test/'])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target');
});

it('picks the declared resource from its scopes when no resource is named', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], grantTypes: ['authorization_code']);

    $claims = riClaims(riCodeFlow($client, ['mcp:tools'], null)->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe(riMcp());
});

it('refuses scopes of two declared resources with no resource as invalid_target', function (): void {
    $this->declareProtectedResource('/mcp', ['mcp:tools']);
    $this->declareProtectedResource('/reports', ['reports:read']);
    $client = $this->makeClient(['mcp:tools', 'reports:read'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'scope' => 'mcp:tools reports:read',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

it('refuses with invalid_scope when nothing requested is accepted by the resource', function (): void {
    $this->declareProtectedResource(scopes: ['mcp:tools']);
    $client = $this->makeClient(['legacy:x'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'scope' => 'legacy:x',
        'resource' => riMcp(),
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
});

// ---------------------------------------------------------------------------------------
// The other grants.
// ---------------------------------------------------------------------------------------

it('honours the resource on client_credentials', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], grantTypes: ['client_credentials']);

    $claims = riClaims($this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'scope' => 'mcp:tools',
        'resource' => riMcp(),
    ])->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe(riMcp());
});

it('honours the resource on the device grant, which used to drop it', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools', 'offline_access'], ClientType::Public, grantTypes: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token']);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($client->client, ['mcp:tools', 'offline_access']);
    $device->approve($result->userCode, 'alice', null);
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id' => $client->client->client_id,
        'device_code' => $result->deviceCode,
        'resource' => riMcp(),
    ])->assertOk();

    expect(riClaims($response->json('access_token'))['aud'])->toBe(riMcp())
        // …and the refresh token it came with is bound to the same audience.
        ->and(RefreshToken::query()->firstOrFail()->audience)->toBe(riMcp());
});

it('honours the resource on token exchange', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], grantTypes: ['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange']);

    // A subject token for a person, issued to this client (and so exchangeable by it).
    $subjectToken = app(TokenIssuer::class)->issueForUser($client->client, 'alice', null, ['mcp:tools'])->token;

    $claims = riClaims($this->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'resource' => riMcp(),
    ])->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe(riMcp());
});

// ---------------------------------------------------------------------------------------
// Refresh tokens stay bound to the original resource.
// ---------------------------------------------------------------------------------------

it('keeps a refresh token bound to its resource, and refuses another before consuming it', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token']);

    $first = riCodeFlow($client, ['mcp:tools', 'offline_access'], riMcp())->assertOk();
    $refresh = $first->json('refresh_token');

    // Naming another audience is refused…
    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client->client_id,
        'refresh_token' => $refresh,
        'resource' => 'https://elsewhere.example.test/api',
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');

    // …and the refresh token was NOT consumed by the refusal: it still works, with the
    // same resource named or none at all, and the new token keeps the original audience.
    $second = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client->client_id,
        'refresh_token' => $refresh,
        'resource' => riMcp(),
    ])->assertOk();

    expect(riClaims($second->json('access_token'))['aud'])->toBe(riMcp());

    $third = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client->client_id,
        'refresh_token' => $second->json('refresh_token'),
    ])->assertOk();

    expect(riClaims($third->json('access_token'))['aud'])->toBe(riMcp());
});

it('treats the issuer as the audience of a refresh token issued with no resource', function (): void {
    $client = $this->makeClient(['openid', 'offline_access'], ClientType::Public, grantTypes: ['authorization_code', 'refresh_token']);
    $refresh = riCodeFlow($client, ['openid', 'offline_access'], null)->assertOk()->json('refresh_token');

    expect(fn () => app(RefreshTokens::class)->rotate($client->client->client_id, $refresh, null, 'https://elsewhere.example.test/'))
        ->toThrow(InvalidAudience::class);

    $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client->client_id,
        'refresh_token' => $refresh,
        'resource' => riIssuer(),
    ])->assertOk();
});

// ---------------------------------------------------------------------------------------
// One resource per request; malformed values refused.
// ---------------------------------------------------------------------------------------

it('refuses a repeated resource parameter in a form body as invalid_target', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], grantTypes: ['client_credentials']);

    $body = http_build_query([
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'scope' => 'mcp:tools',
    ]).'&resource='.urlencode(riMcp()).'&resource='.urlencode('https://other.example.test/');

    // What PHP's parser would hand the request: the LAST repeated value only.
    $parsed = [];
    parse_str($body, $parsed);

    $response = $this->call('POST', '/oauth/token', $parsed, [], [], [
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        'HTTP_ACCEPT' => 'application/json',
    ], $body);

    $response->assertStatus(400)->assertJsonPath('error', 'invalid_target');
    expect($response->json('error_description'))->toContain('Only one resource');
});

it('refuses several resources given as an array as invalid_target', function (): void {
    $client = $this->makeClient(['legacy:x'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'resource' => ['https://a.example.test/', 'https://b.example.test/'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

it('refuses a malformed resource as invalid_target', function (string $resource): void {
    $client = $this->makeClient(['legacy:x'], grantTypes: ['client_credentials']);

    $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'resource' => $resource,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');
})->with([
    'relative' => '/mcp',
    'fragment' => 'https://h.example.test/mcp#x',
    'no host' => 'urn:example:mcp',
]);

it('counts repeated resource keys in a query string too', function (): void {
    $request = Request::create('/oauth/authorize?resource=https%3A%2F%2Fa.test%2F&resource=https%3A%2F%2Fb.test%2F');

    expect(fn () => ResourceParameter::fromRequest($request))->toThrow(InvalidAudience::class);

    expect(ResourceParameter::fromRequest(Request::create('/oauth/authorize?resource=https%3A%2F%2Fa.test%2F')))->toBe('https://a.test/')
        ->and(ResourceParameter::fromRequest(Request::create('/oauth/authorize')))->toBeNull()
        ->and(ResourceParameter::fromValue(['https://a.test/']))->toBe('https://a.test/')
        ->and(ResourceParameter::fromValue(''))->toBeNull();
});

// ---------------------------------------------------------------------------------------
// Who may be audienced where.
// ---------------------------------------------------------------------------------------

it('refuses a self-registered client a resource this environment does not serve', function (): void {
    $client = riSelfRegistered(['openid']);

    expect(fn () => app(AudienceResolver::class)->resolve($client->client, ['openid'], 'https://bank.example.test/'))
        ->toThrow(InvalidAudience::class, 'is not served');

    // The issuer itself is always served.
    expect(app(AudienceResolver::class)->resolve($client->client, ['openid'], riIssuer())->resource)->toBe(riIssuer());
});

it('refuses a self-registered client a declared resource that does not accept them', function (): void {
    $this->declareProtectedResource(dynamicClients: false);
    $client = riSelfRegistered(['openid']);

    try {
        app(AudienceResolver::class)->resolve($client->client, ['openid'], riMcp());
        $this->fail('expected invalid_target');
    } catch (InvalidAudience $e) {
        expect($e->error)->toBe('invalid_target')
            ->and($e->getMessage())->toContain('does not accept dynamically registered clients');
    }
});

it('never lets a self-registered client carry a reserved scope to a declared resource', function (): void {
    $this->declareProtectedResource(scopes: ['mcp:tools', 'vault.lease']);
    $client = riSelfRegistered(['openid']);

    $resolved = app(AudienceResolver::class)->resolve($client->client, ['mcp:tools', 'vault.lease'], riMcp());

    expect($resolved->scopes)->toBe(['mcp:tools']);
});

it('keeps the RFC 8707 pass-through for operator clients unless told to refuse', function (): void {
    $client = $this->makeClient(['legacy:x'], grantTypes: ['client_credentials']);

    $request = fn () => $this->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'resource' => 'https://anything.example.test/v1',
    ]);

    expect(riClaims($request()->assertOk()->json('access_token'))['aud'])->toBe('https://anything.example.test/v1');

    config(['cbox-id.oauth.resource_indicators.unknown_resources' => 'refuse']);

    $request()->assertStatus(400)->assertJsonPath('error', 'invalid_target');
});

// ---------------------------------------------------------------------------------------
// PAR checks the resource on the back channel.
// ---------------------------------------------------------------------------------------

it('stores a pushed request with its one validated resource', function (): void {
    $this->declareProtectedResource();
    $client = $this->makeClient(['mcp:tools'], ClientType::Public, grantTypes: ['authorization_code']);

    $this->postJson('/oauth/par', [
        'client_id' => $client->client->client_id,
        'response_type' => 'code',
        'redirect_uri' => 'https://app.test/cb',
        'scope' => 'mcp:tools',
        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method' => 'S256',
        'resource' => riMcp(),
    ])->assertStatus(201);

    expect(PushedAuthorizationRequest::query()->firstOrFail()->params['resource'])->toBe(riMcp());
});

it('refuses a pushed request whose resource the client may not be audienced to', function (): void {
    $this->declareProtectedResource(dynamicClients: false);
    $client = riSelfRegistered(['mcp:tools']);

    $this->postJson('/oauth/par', [
        'client_id' => $client->client->client_id,
        'response_type' => 'code',
        'redirect_uri' => 'https://app.test/cb',
        'scope' => 'mcp:tools',
        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'code_challenge_method' => 'S256',
        'resource' => riMcp(),
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');

    $this->postJson('/oauth/par', [
        'client_id' => $client->client->client_id,
        'response_type' => 'code',
        'redirect_uri' => 'https://app.test/cb',
        'code_challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        'resource' => ['https://a.example.test/', 'https://b.example.test/'],
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_target');

    expect(PushedAuthorizationRequest::query()->count())->toBe(0);
});

it('refuses to bind a code to a malformed resource', function (): void {
    expect(fn () => app(AuthorizationCodes::class)->issue(
        'client', 'alice', null, 'https://app.test/cb', [],
        Base64Url::encode(hash('sha256', str_repeat('v', 50), true)),
        resource: '/mcp',
    ))->toThrow(InvalidGrant::class);
});
