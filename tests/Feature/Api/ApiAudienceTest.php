<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\OAuthServer\Models\RefreshToken;
use Cbox\Id\OAuthServer\ValueObjects\ApiScopeDefinition;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * APIs (resource servers) own their scopes, and the audience of every access token is
 * decided by one resolver. These tests drive the token endpoint for every grant that mints
 * an access token, because the defect this closes lived exactly there: `resource` was only
 * checked for being an absolute URI before it became `aud`, and a scope was free text.
 */

const API_TAX = 'https://tax.example.test';
const API_CADASTRE = 'https://cadastre.example.test';

if (! function_exists('audClaims')) {
    /**
     * @return array<string, mixed>
     */
    function audClaims(string $jwt): array
    {
        return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
    }
}

function audIssuer(): string
{
    return app(IssuerResolver::class)->issuer();
}

/**
 * @param  array<string, string>  $extra
 */
function audClientCredentials(RegisteredClient $client, string $scope, array $extra = []): TestResponse
{
    return test()->postJson('/oauth/token', [
        'grant_type' => 'client_credentials',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'scope' => $scope,
        ...$extra,
    ]);
}

/**
 * Run the authorization-code grant end to end for `$scopes`, optionally bound to a resource.
 *
 * @param  list<string>  $scopes
 */
function audAuthorizationCode(RegisteredClient $client, array $scopes, ?string $organizationId = null, ?string $resource = null, string $user = 'alice'): TestResponse
{
    $verifier = 'a-sufficiently-long-code-verifier-1234567890';

    $code = app(AuthorizationCodes::class)->issue(
        $client->client->client_id,
        $user,
        $organizationId,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', $verifier, true)),
        resource: $resource,
    );

    return test()->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ]);
}

/**
 * A tenant-owned client that already holds `$scopes` as free text — written before the
 * APIs that own them were registered, which is the state every existing deployment is in.
 *
 * @param  list<string>  $scopes
 * @param  list<string>  $grants
 */
function audLegacyTenantClient(string $organizationId, array $scopes, array $grants = ['client_credentials', 'authorization_code', 'refresh_token']): RegisteredClient
{
    return test()->makeClient($scopes, grantTypes: $grants, organizationId: $organizationId);
}

function audDeclareApp(string $clientId, string $permission, string $role): void
{
    app(AppManifests::class)->sync($clientId, app(ManifestParser::class)->parse([
        'version' => '1',
        'permissions' => [['key' => $permission, 'description' => null]],
        'roles' => [['key' => $role, 'name' => ucfirst($role), 'permissions' => [$permission]]],
    ]));
}

// ---------------------------------------------------------------------------------------
// Back-compat: an environment with no registered APIs behaves exactly as before.
// ---------------------------------------------------------------------------------------

it('leaves an environment with no registered APIs exactly as it was', function (): void {
    $client = $this->makeClient(['legacy:read', 'legacy:write', 'openid'], grantTypes: ['client_credentials', 'authorization_code', 'refresh_token']);

    // No resource: aud is the issuer, scope as granted.
    $plain = audClaims(audClientCredentials($client, 'legacy:read legacy:write')->assertOk()->json('access_token'));
    expect($plain['aud'])->toBe(audIssuer())
        ->and($plain['scope'])->toBe('legacy:read legacy:write');

    // Any absolute-URI resource: aud is that resource verbatim, scope untouched.
    $bound = audClaims(audClientCredentials($client, 'legacy:read', ['resource' => 'https://anything.example.test/v1'])->assertOk()->json('access_token'));
    expect($bound['aud'])->toBe('https://anything.example.test/v1')
        ->and($bound['scope'])->toBe('legacy:read');

    // A user grant with openid and a resource: a single-valued aud, as before — the
    // issuer is added only for a REGISTERED API's audience.
    $user = audClaims(audAuthorizationCode($client, ['openid', 'legacy:read', 'offline_access'], resource: 'https://anything.example.test/v1')->assertOk()->json('access_token'));
    expect($user['aud'])->toBe('https://anything.example.test/v1')
        ->and($user['scope'])->toBe('openid legacy:read');

    // The refresh token remembers the same audience it always did.
    expect(RefreshToken::query()->sole()->audience)->toBe('https://anything.example.test/v1');
});

it('mints byte-for-byte the same claims whether or not an unrelated API is registered', function (): void {
    $org = $this->makeOrganization();
    $client = $this->makeClient(['legacy:read', 'openid'], grantTypes: ['client_credentials'], organizationId: $org->id);
    $issuer = app(TokenIssuer::class);

    $shape = fn (array $claims): array => array_intersect_key($claims, array_flip(['aud', 'scope', 'org', 'client_id', 'roles', 'permissions']));

    $before = [
        $shape(audClaims($issuer->issueClientCredentials($client->client, ['legacy:read'])->token)),
        $shape(audClaims($issuer->issueClientCredentials($client->client, ['legacy:read'], 'https://x.example.test')->token)),
        $shape(audClaims($issuer->issueForUser($client->client, 'alice', $org->id, ['openid', 'legacy:read'])->token)),
    ];

    $this->makeApi(API_TAX, ['tax:read', 'tax:assess' => false]);

    $after = [
        $shape(audClaims($issuer->issueClientCredentials($client->client, ['legacy:read'])->token)),
        $shape(audClaims($issuer->issueClientCredentials($client->client, ['legacy:read'], 'https://x.example.test')->token)),
        $shape(audClaims($issuer->issueForUser($client->client, 'alice', $org->id, ['openid', 'legacy:read'])->token)),
    ];

    expect($after)->toBe($before);
});

// ---------------------------------------------------------------------------------------
// The attack: a tenant squats a scope that belongs to someone else's API.
// ---------------------------------------------------------------------------------------

it('refuses a tenant client that squatted tax:assess when it names the tax API', function (): void {
    $org = $this->makeOrganization('Tenant');
    $squatter = audLegacyTenantClient($org->id, ['tax:assess']);
    $this->makeApi(API_TAX, ['tax:read', 'tax:assess' => false]);

    audClientCredentials($squatter, 'tax:assess', ['resource' => API_TAX])
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope')
        ->assertJsonPath('error_description', 'None of the requested scopes may be granted to this client for the requested audience.');

    // And without naming the API: the scope is still dropped rather than defaulting the
    // token onto the tax API's audience.
    audClientCredentials($squatter, 'tax:assess')
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_scope');
});

it('drops the squatted scope from a user token and keeps the login working', function (): void {
    $org = $this->makeOrganization('Tenant');
    $squatter = audLegacyTenantClient($org->id, ['openid', 'tax:assess']);
    $this->makeApi(API_TAX, ['tax:read', 'tax:assess' => false]);

    $response = audAuthorizationCode($squatter, ['openid', 'tax:assess'], $org->id, API_TAX)->assertOk();
    $claims = audClaims($response->json('access_token'));

    expect($claims['scope'])->toBe('openid')
        ->and($claims['aud'])->toBe([API_TAX, audIssuer()])
        ->and($response->json('scope'))->toBe('openid');
});

it('grants the same scope to an environment-owned client', function (): void {
    $platform = $this->makeClient(['tax:assess']);
    $this->makeApi(API_TAX, ['tax:read', 'tax:assess' => false]);

    $claims = audClaims(audClientCredentials($platform, 'tax:assess', ['resource' => API_TAX])->assertOk()->json('access_token'));

    expect($claims['scope'])->toBe('tax:assess')
        ->and($claims['aud'])->toBe(API_TAX);
});

it('grants a tenant-requestable scope of an environment-owned API to a tenant client', function (): void {
    $org = $this->makeOrganization('Tenant');
    $this->makeApi(API_TAX, ['tax:read', 'tax:assess' => false]);
    $tenant = $this->makeClient(['tax:read'], organizationId: $org->id);

    $claims = audClaims(audClientCredentials($tenant, 'tax:read')->assertOk()->json('access_token'));

    expect($claims['scope'])->toBe('tax:read')
        ->and($claims['aud'])->toBe(API_TAX);
});

it("never grants one tenant's API scopes to another tenant's client", function (): void {
    $owner = $this->makeOrganization('Owner');
    $other = $this->makeOrganization('Other');
    $squatter = audLegacyTenantClient($other->id, ['books:read']);
    $this->makeApi('https://books.example.test', ['books:read'], organizationId: $owner->id);
    $ownersClient = $this->makeClient(['books:read'], organizationId: $owner->id);

    audClientCredentials($squatter, 'books:read')->assertStatus(400)->assertJsonPath('error', 'invalid_scope');

    expect(audClaims(audClientCredentials($ownersClient, 'books:read')->assertOk()->json('access_token'))['aud'])
        ->toBe('https://books.example.test');
});

// ---------------------------------------------------------------------------------------
// Audience rules.
// ---------------------------------------------------------------------------------------

it('defaults aud to the one API the requested scopes belong to', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['tax:read']);

    $claims = audClaims(audClientCredentials($client, 'tax:read')->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe(API_TAX);
});

it('refuses scopes of two APIs with no resource, and narrows to the one resource names', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $this->makeApi(API_CADASTRE, ['cadastre:read']);
    $client = $this->makeClient(['tax:read', 'cadastre:read']);

    audClientCredentials($client, 'tax:read cadastre:read')
        ->assertStatus(400)
        ->assertJsonPath('error', 'invalid_target')
        ->assertJsonPath('error_description', 'The requested scopes belong to more than one API (https://cadastre.example.test, https://tax.example.test). Name the one this token is for with the resource parameter.');

    $response = audClientCredentials($client, 'tax:read cadastre:read', ['resource' => API_CADASTRE])->assertOk();
    expect(audClaims($response->json('access_token'))['scope'])->toBe('cadastre:read')
        ->and($response->json('scope'))->toBe('cadastre:read');
});

it('intersects with the named API and never lets a free-text scope ride on its audience', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['openid', 'tax:read', 'legacy:admin'], grantTypes: ['authorization_code', 'client_credentials']);

    $claims = audClaims(audAuthorizationCode($client, ['openid', 'tax:read', 'legacy:admin'], resource: API_TAX)->assertOk()->json('access_token'));

    expect($claims['scope'])->toBe('openid tax:read')
        ->and($claims['aud'])->toBe([API_TAX, audIssuer()]);

    // And with no resource, the registered scope still defaults the audience to the API,
    // which again leaves the free-text scope behind.
    $defaulted = audClaims(audClientCredentials($client, 'tax:read legacy:admin')->assertOk()->json('access_token'));
    expect($defaulted['scope'])->toBe('tax:read')
        ->and($defaulted['aud'])->toBe(API_TAX);
});

it('drops registered scopes when resource names an unregistered audience', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['tax:read', 'legacy:read']);

    $claims = audClaims(audClientCredentials($client, 'tax:read legacy:read', ['resource' => 'https://elsewhere.example.test'])->assertOk()->json('access_token'));

    expect($claims['scope'])->toBe('legacy:read')
        ->and($claims['aud'])->toBe('https://elsewhere.example.test');
});

it('lets UserInfo accept a token audienced to an API that carries openid', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['openid', 'tax:read'], grantTypes: ['authorization_code']);

    $token = audAuthorizationCode($client, ['openid', 'tax:read'])->assertOk()->json('access_token');

    expect(audClaims($token)['aud'])->toBe([API_TAX, audIssuer()]);
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonPath('sub', 'alice');

    // Without openid the token is for the API alone, and UserInfo refuses it.
    $apiOnly = audAuthorizationCode($client, ['tax:read'])->assertOk()->json('access_token');
    expect(audClaims($apiOnly)['aud'])->toBe(API_TAX);
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$apiOnly])->assertUnauthorized();
});

// ---------------------------------------------------------------------------------------
// RBAC: a token for an API carries the API's app's roles and permissions.
// ---------------------------------------------------------------------------------------

it("stamps the API's app permissions, not the requesting app's, into a token for that API", function (): void {
    $org = $this->makeOrganization();
    $cadastreApp = $this->makeClient(['openid']);
    $taxApp = $this->makeClient(['openid', 'cadastre:read'], grantTypes: ['authorization_code']);

    audDeclareApp($cadastreApp->client->client_id, 'parcels:read', 'surveyor');
    audDeclareApp($taxApp->client->client_id, 'returns:file', 'filer');

    foreach ([$cadastreApp, $taxApp] as $app) {
        $role = Role::query()->where('client_id', $app->client->client_id)->firstOrFail();
        app(Roles::class)->assign($org->id, 'alice', $role->id);
    }

    $this->makeApi(API_CADASTRE, ['cadastre:read'], clientId: $cadastreApp->client->client_id);

    $forCadastre = audClaims(audAuthorizationCode($taxApp, ['openid', 'cadastre:read'], $org->id, API_CADASTRE)->assertOk()->json('access_token'));
    expect($forCadastre['roles'])->toBe(['surveyor'])
        ->and($forCadastre['permissions'])->toBe(['parcels:read']);

    // The same app's own login token still carries its own roles.
    $own = audClaims(audAuthorizationCode($taxApp, ['openid'], $org->id)->assertOk()->json('access_token'));
    expect($own['roles'])->toBe(['filer'])
        ->and($own['permissions'])->toBe(['returns:file']);
});

// ---------------------------------------------------------------------------------------
// Every grant that mints an access token goes through the resolver.
// ---------------------------------------------------------------------------------------

it('resolves the audience for the device grant', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['openid', 'tax:read', 'legacy:x'], ClientType::Public, grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);
    $device = app(DeviceAuthorization::class);
    $result = $device->request($client->client, ['openid', 'tax:read', 'legacy:x']);
    $device->approve($result->userCode, 'alice', null);
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $claims = audClaims($this->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id' => $client->client->client_id,
        'device_code' => $result->deviceCode,
    ])->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe([API_TAX, audIssuer()])
        ->and($claims['scope'])->toBe('openid tax:read');
});

it('resolves the audience for the CIBA grant', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['openid', 'tax:read'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('bob@example.test');
    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($client->client, ['openid', 'tax:read'], $user->id);
    $ciba->approve($result->requestId, $user->id);
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $claims = audClaims($this->postJson('/oauth/token', [
        'grant_type' => 'urn:openid:params:grant-type:ciba',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertOk()->json('access_token'));

    expect($claims['aud'])->toBe([API_TAX, audIssuer()]);
});

it('resolves the audience for token exchange and echoes what the new token carries', function (): void {
    $this->makeApi(API_TAX, ['tax:read']);
    $client = $this->makeClient(['tax:read', 'legacy:x'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange']);
    $subject = app(TokenIssuer::class)->issueForUser($client->client, 'alice', null, ['legacy:x'])->token;

    // The subject token holds only the free-text scope; exchanging it onto the tax API's
    // audience would be a free-text scope riding on a registered audience.
    $this->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'resource' => API_TAX,
    ])->assertStatus(400)->assertJsonPath('error', 'invalid_scope');
});

it('never widens scope or audience on refresh, even when the API later opens up', function (): void {
    $org = $this->makeOrganization('Tenant');
    $client = audLegacyTenantClient($org->id, ['openid', 'offline_access', 'tax:read', 'tax:file']);
    $api = $this->makeApi(API_TAX, ['tax:read', 'tax:file' => false]);

    $first = audAuthorizationCode($client, ['openid', 'offline_access', 'tax:read', 'tax:file'], $org->id)->assertOk();
    expect(audClaims($first->json('access_token'))['scope'])->toBe('openid offline_access tax:read');

    $stored = RefreshToken::query()->sole();
    expect($stored->audience)->toBe(API_TAX)
        ->and($stored->scopes)->toBe(['openid', 'offline_access', 'tax:read']);

    // The environment now lets tenants request tax:file. The refresh token was granted
    // without it, and a refresh re-mints what was granted — nothing more.
    app(Apis::class)->defineScope($api, new ApiScopeDefinition('tax:file'));

    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'refresh_token' => $first->json('refresh_token'),
    ])->assertOk();

    $claims = audClaims($refreshed->json('access_token'));
    expect($claims['scope'])->toBe('openid offline_access tax:read')
        ->and($claims['aud'])->toBe([API_TAX, audIssuer()]);
});

it('keeps an existing client that holds a newly registered scope editable', function (): void {
    $org = $this->makeOrganization('Tenant');
    $squatter = audLegacyTenantClient($org->id, ['tax:assess']);
    $this->makeApi(API_TAX, ['tax:assess' => false]);

    // Renaming it does not trip the save guard — only newly added scopes are judged.
    $model = Client::query()->findOrFail($squatter->client->id);
    $model->name = 'Renamed';
    $model->save();

    expect($model->fresh()?->name)->toBe('Renamed');
});
