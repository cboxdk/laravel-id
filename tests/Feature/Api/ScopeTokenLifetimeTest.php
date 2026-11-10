<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Support\AccessTokenLifetime;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\OAuthServer\ValueObjects\RegisteredClient;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * `cbox-id.oauth.scope_token_ttls`: a token whose scopes are EXACTLY a configured set gets
 * that set's lifetime — the app switcher's read-only `account:apps:read` grant by default —
 * on token exchange and on the authorization-code flow at the `/mcp` resource alike. One
 * scope more and the normal lifetime stands; the ceiling always applies.
 */

const STL_CATALOG = 'account:apps:read';

beforeEach(function (): void {
    User::query()->create(['id' => 'alice', 'email' => 'alice@tokens.test', 'status' => UserStatus::Active]);
    $this->declareProtectedResource(scopes: [STL_CATALOG, 'mcp:tools']);
});

function stlMcp(): string
{
    return rtrim(app(IssuerResolver::class)->issuer(), '/').'/mcp';
}

function stlClient(?int $ttl = null): RegisteredClient
{
    return app(ClientRegistry::class)->register(new NewClient(
        name: 'App switcher',
        redirectUris: ['https://app.test/cb'],
        grantTypes: ['authorization_code', 'urn:ietf:params:oauth:grant-type:token-exchange'],
        scopes: ['openid', STL_CATALOG, 'mcp:tools'],
        accessTokenTtl: $ttl,
    ));
}

function stlLifetime(TestResponse $response): int
{
    $response->assertOk();
    $claims = (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', (string) $response->json('access_token'))[1]), true);
    $lifetime = $claims['exp'] - $claims['iat'];

    // The response, the signed claim and the revocation record agree.
    expect($response->json('expires_in'))->toBe($lifetime)
        ->and(AccessToken::query()->where('jti', $claims['jti'])->firstOrFail()->expires_at->getTimestamp())->toBe($claims['exp']);

    return $lifetime;
}

function stlExchange(object $test, RegisteredClient $client, string $scope): TestResponse
{
    $subject = app(TokenIssuer::class)->issueForUser($client->client, 'alice', null, ['openid', STL_CATALOG, 'mcp:tools'])->token;

    return $test->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'subject_token' => $subject,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
        'scope' => $scope,
        'resource' => stlMcp(),
    ]);
}

/** @param list<string> $scopes */
function stlCodeFlow(object $test, RegisteredClient $client, array $scopes): TestResponse
{
    $verifier = str_repeat('v', 50);
    $code = app(AuthorizationCodes::class)->issue(
        $client->client->client_id,
        'alice',
        null,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', $verifier, true)),
        resource: stlMcp(),
    );

    return $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $client->client->client_id,
        'client_secret' => $client->secret,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => $verifier,
    ]);
}

it('gives an exactly account:apps:read token the catalog lifetime on token exchange', function (): void {
    expect(stlLifetime(stlExchange($this, stlClient(), STL_CATALOG)))->toBe(43200);
});

it('gives an exactly account:apps:read token the catalog lifetime on the authorization-code flow at /mcp', function (): void {
    expect(stlLifetime(stlCodeFlow($this, stlClient(), [STL_CATALOG])))->toBe(43200);
});

it('keeps the normal lifetime for a token with any scope beyond the configured set', function (): void {
    $client = stlClient();

    expect(stlLifetime(stlExchange($this, $client, STL_CATALOG.' mcp:tools')))->toBe(900)
        ->and(stlLifetime(stlCodeFlow($this, $client, ['openid', STL_CATALOG])))->toBe(900);
});

it('wins over the client\'s own lifetime', function (): void {
    $client = stlClient(300);

    expect(stlLifetime(stlExchange($this, $client, STL_CATALOG)))->toBe(43200)
        ->and(stlLifetime(stlExchange($this, $client, 'mcp:tools')))->toBe(300);
});

it('is clamped to the ceiling', function (): void {
    config()->set('cbox-id.oauth.max_access_token_ttl', 3600);

    expect(stlLifetime(stlExchange($this, stlClient(), STL_CATALOG)))->toBe(3600);
});

it('is off when its entry is zero', function (): void {
    config()->set('cbox-id.oauth.scope_token_ttls', [STL_CATALOG => 0]);

    expect(stlLifetime(stlExchange($this, stlClient(), STL_CATALOG)))->toBe(900);
});

it('matches a multi-scope set regardless of order and only exactly', function (): void {
    config()->set('cbox-id.oauth.scope_token_ttls', ['b:read  a:read' => 7200]);

    expect(AccessTokenLifetime::forScopes(['a:read', 'b:read']))->toBe(7200)
        ->and(AccessTokenLifetime::forScopes(['b:read', 'a:read', 'a:read']))->toBe(7200)
        ->and(AccessTokenLifetime::forScopes(['a:read']))->toBeNull()
        ->and(AccessTokenLifetime::forScopes(['a:read', 'b:read', 'c:read']))->toBeNull()
        ->and(AccessTokenLifetime::forScopes([]))->toBeNull();
});

it('ships account:apps:read at 12 hours by default', function (): void {
    expect(AccessTokenLifetime::forScopes([STL_CATALOG]))->toBe(43200);
});
