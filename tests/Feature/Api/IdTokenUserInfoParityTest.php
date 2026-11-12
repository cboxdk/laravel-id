<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The ID Token answers everything UserInfo answers, for the scopes that were granted.
 *
 * WHY THIS FILE EXISTS. A relying party that signs a person in used to make two calls: the
 * code exchange, then UserInfo for the email, name, roles and organizations the ID Token
 * did not carry. A client that skips the second call takes EVERYTHING from the ID Token, so
 * a token with `email` and no `roles` signs the person in without their roles. The claims
 * therefore come from one place (IdentityClaims) for both, and these tests compare the
 * signed ID Token with the UserInfo answer for the same grant, claim by claim.
 */
const PARITY_VERIFIER = 'a-sufficiently-long-code-verifier-1234567890';

beforeEach(function (): void {
    User::query()->create([
        'id' => 'alice',
        'email' => 'alice@parity.test',
        'name' => 'Alice Example',
        'email_verified_at' => now(),
        'status' => UserStatus::Active,
    ]);
});

/**
 * Sign alice in with $scopes and return the verified ID Token claims beside the UserInfo
 * answer for the access token of the same exchange.
 *
 * @param  list<string>  $scopes
 * @return array{id: array<string, mixed>, userinfo: array<string, mixed>, refresh: ?string}
 */
function parityFor(object $test, string $clientId, ?string $organizationId, array $scopes): array
{
    $code = app(AuthorizationCodes::class)->issue(
        $clientId,
        'alice',
        $organizationId,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', PARITY_VERIFIER, true)),
        'S256',
        'a-nonce',
        1_700_000_000,
        ['pwd'],
    );

    $tokens = $test->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'code' => $code,
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => PARITY_VERIFIER,
    ])->assertOk();

    return [
        'id' => parityClaims((string) $tokens->json('id_token')),
        'userinfo' => parityUserInfo($test, (string) $tokens->json('access_token')),
        'refresh' => is_string($tokens->json('refresh_token')) ? $tokens->json('refresh_token') : null,
    ];
}

/** @return array<string, mixed> */
function parityClaims(string $idToken): array
{
    // Through JSON, so a nested object reads as an array, as UserInfo's answer does.
    /** @var array<string, mixed> $claims */
    $claims = json_decode((string) json_encode(app(TokenSigner::class)->verify($idToken, [SigningAlg::RS256])->all()), true);

    return $claims;
}

/** @return array<string, mixed> */
function parityUserInfo(object $test, string $accessToken): array
{
    /** @var array<string, mixed> $claims */
    $claims = $test->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$accessToken])->assertOk()->json();

    return $claims;
}

/** Alice in two organizations, with a role and two permissions in the first for $clientId. */
function parityWorld(string $clientId): string
{
    $acme = app(Organizations::class)->create(new NewOrganization(name: 'Acme Inc', slug: 'acme', type: OrganizationType::Customer));
    $globex = app(Organizations::class)->create(new NewOrganization(name: 'Globex', slug: 'globex', type: OrganizationType::Customer));
    app(Memberships::class)->add($acme->id, 'alice', MembershipRole::Admin);
    app(Memberships::class)->add($globex->id, 'alice', MembershipRole::Member);

    app(AppManifests::class)->sync($clientId, app(ManifestParser::class)->parse([
        'version' => '1',
        'permissions' => [
            ['key' => 'invoices:create', 'description' => null],
            ['key' => 'invoices:read', 'description' => null],
        ],
        'roles' => [
            ['key' => 'billing-admin', 'name' => 'Billing Admin', 'permissions' => ['invoices:create', 'invoices:read']],
        ],
    ]));
    $role = Role::query()->where('client_id', $clientId)->where('key', 'billing-admin')->firstOrFail();
    app(Roles::class)->assign($acme->id, 'alice', $role->id);

    return $acme->id;
}

it('carries every claim UserInfo returns, with the same value', function (array $scopes): void {
    $clientId = $this->makeClient($scopes, ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;
    $organizationId = parityWorld($clientId);

    $answers = parityFor($this, $clientId, $organizationId, $scopes);

    expect($answers['userinfo'])->not->toBeEmpty();

    foreach ($answers['userinfo'] as $claim => $value) {
        expect($answers['id'])->toHaveKey($claim)
            ->and($answers['id'][$claim])->toEqual($value, "The ID Token's `{$claim}` differs from UserInfo's.");
    }
})->with([
    'openid' => [['openid']],
    'email' => [['openid', 'email']],
    'profile' => [['openid', 'profile']],
    'email and profile' => [['openid', 'email', 'profile']],
    'organizations' => [['openid', 'organizations']],
    'feature flags' => [['openid', 'feature_flags']],
    'everything' => [['openid', 'email', 'profile', 'organizations', 'feature_flags']],
]);

it('names the person, their roles and their organizations in the ID Token', function (): void {
    $scopes = ['openid', 'email', 'profile', 'organizations'];
    $clientId = $this->makeClient($scopes, ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;
    $organizationId = parityWorld($clientId);

    $id = parityFor($this, $clientId, $organizationId, $scopes)['id'];

    expect($id['email'])->toBe('alice@parity.test')
        ->and($id['email_verified'])->toBeTrue()
        ->and($id['name'])->toBe('Alice Example')
        ->and($id['org'])->toBe($organizationId)
        ->and($id['org_slug'])->toBe('acme')
        ->and($id['org_name'])->toBe('Acme Inc')
        ->and($id['org_role'])->toBe('admin')
        ->and($id['roles'])->toBe(['billing-admin'])
        ->and($id['permissions'])->toBe(['invoices:create', 'invoices:read'])
        ->and(collect($id['organizations'])->sortBy('slug')->values()->all())->toEqual([
            ['id' => $organizationId, 'name' => 'Acme Inc', 'role' => 'admin', 'slug' => 'acme'],
            ['id' => collect($id['organizations'])->firstWhere('slug', 'globex')['id'], 'name' => 'Globex', 'role' => 'member', 'slug' => 'globex'],
        ]);
});

it('keeps a claim out of the ID Token when its scope was not granted', function (): void {
    $clientId = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;
    $organizationId = parityWorld($clientId);

    $id = parityFor($this, $clientId, $organizationId, ['openid'])['id'];

    expect($id)->not->toHaveKey('email')
        ->and($id)->not->toHaveKey('email_verified')
        ->and($id)->not->toHaveKey('name')
        ->and($id)->not->toHaveKey('organizations')
        ->and($id)->not->toHaveKey('feature_flags')
        // Not behind a scope at UserInfo either: what the person may do in THIS app.
        ->and($id['roles'])->toBe(['billing-admin']);
});

it('says an empty organization list when the scope is granted and the person belongs to none', function (): void {
    $scopes = ['openid', 'organizations'];
    $clientId = $this->makeClient($scopes, ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;

    $answers = parityFor($this, $clientId, null, $scopes);

    expect($answers['id']['organizations'])->toBe([])
        ->and($answers['userinfo']['organizations'])->toBe([])
        ->and($answers['id'])->not->toHaveKey('roles')
        ->and($answers['id'])->not->toHaveKey('org_slug');
});

it("does not put another app's roles in this app's ID Token", function (): void {
    $billing = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;
    $other = $this->makeClient(['openid'], ClientType::Public, grantTypes: ['authorization_code'])->client->client_id;
    $organizationId = parityWorld($billing);

    $id = parityFor($this, $other, $organizationId, ['openid'])['id'];

    expect($id)->not->toHaveKey('roles')
        ->and($id)->not->toHaveKey('permissions');
});

it('answers the same after a refresh', function (): void {
    $scopes = ['openid', 'email', 'profile', 'organizations', 'offline_access'];
    $clientId = $this->makeClient($scopes, ClientType::Public, grantTypes: ['authorization_code', 'refresh_token'])->client->client_id;
    $organizationId = parityWorld($clientId);
    $first = parityFor($this, $clientId, $organizationId, $scopes);

    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'refresh_token' => $first['refresh'],
    ])->assertOk();

    $id = parityClaims((string) $refreshed->json('id_token'));

    foreach (parityUserInfo($this, (string) $refreshed->json('access_token')) as $claim => $value) {
        expect($id)->toHaveKey($claim)->and($id[$claim])->toEqual($value);
    }

    expect($id['email'])->toBe('alice@parity.test')
        ->and($id['roles'])->toBe(['billing-admin']);
});
