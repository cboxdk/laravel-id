<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\PipelineOutcome;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\Kernel\Tenancy\Contracts\TenantContext;
use Cbox\Id\Kernel\Tenancy\GenericTenant;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Cbox\Id\OAuthServer\Models\DeviceCode;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Models\Membership;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * `org_role` — the subject's membership tier in the bound organization — on every token
 * that has a person behind it, on the ID token and on UserInfo. An app built on Cbox ID
 * could not tell an owner from an admin without a second call, so each one either made
 * that call on every request or guessed.
 */

/**
 * @return array<string, mixed>
 */
function orgRoleClaims(string $jwt): array
{
    return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
}

const ORG_ROLE_VERIFIER = 'a-sufficiently-long-code-verifier-for-org-role-1234';

function orgRoleCode(string $clientId, string $userId, ?string $organizationId, array $scopes): string
{
    return app(AuthorizationCodes::class)->issue(
        $clientId,
        $userId,
        $organizationId,
        'https://app.test/cb',
        $scopes,
        Base64Url::encode(hash('sha256', ORG_ROLE_VERIFIER, true)),
        'S256',
    );
}

it('stamps the tier on the access token, the ID token and UserInfo after an authorization code', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Admin);
    $registered = $this->makeClient(['openid', 'offline_access'], grantTypes: ['authorization_code', 'refresh_token']);
    $clientId = $registered->client->client_id;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'authorization_code',
        'client_id' => $clientId,
        'client_secret' => $registered->secret,
        'code' => orgRoleCode($clientId, 'alice', $org->id, ['openid', 'offline_access']),
        'redirect_uri' => 'https://app.test/cb',
        'code_verifier' => ORG_ROLE_VERIFIER,
    ])->assertOk();

    expect(orgRoleClaims($response->json('access_token'))['org_role'] ?? null)->toBe('admin')
        ->and(orgRoleClaims($response->json('id_token'))['org_role'] ?? null)->toBe('admin');

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$response->json('access_token')])
        ->assertOk()
        ->assertJsonPath('org', $org->id)
        ->assertJsonPath('org_role', 'admin');

    // A refresh re-reads the tier: an ownership transfer since the login shows up in the
    // next token, not only in the next login.
    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Owner);
    app(Memberships::class)->transferOwnership($org->id, 'bob', 'alice');

    $refreshed = $this->postJson('/oauth/token', [
        'grant_type' => 'refresh_token',
        'client_id' => $clientId,
        'client_secret' => $registered->secret,
        'refresh_token' => $response->json('refresh_token'),
    ])->assertOk();

    expect(orgRoleClaims($refreshed->json('access_token'))['org_role'] ?? null)->toBe('owner')
        ->and(orgRoleClaims($refreshed->json('id_token'))['org_role'] ?? null)->toBe('owner');
});

it('stamps the tier after a device grant', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Developer);
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:ietf:params:oauth:grant-type:device_code']);

    $device = app(DeviceAuthorization::class);
    $result = $device->request($registered->client, ['openid']);
    $device->approve($result->userCode, 'alice', $org->id);
    DeviceCode::query()->update(['last_polled_at' => now()->subMinute()]);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'device_code' => $result->deviceCode,
    ])->assertOk();

    expect(orgRoleClaims($response->json('access_token'))['org_role'] ?? null)->toBe('developer')
        ->and(orgRoleClaims($response->json('id_token'))['org_role'] ?? null)->toBe('developer');
});

it('stamps the tier after a CIBA grant', function (): void {
    $org = $this->makeOrganization();
    $user = $this->makeUser('ciba-org-role@example.test');
    app(Memberships::class)->add($org->id, $user->id, MembershipRole::Viewer);
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);

    $ciba = app(BackchannelAuthentication::class);
    $result = $ciba->request($registered->client, ['openid'], $user->id);
    $ciba->approve($result->requestId, $user->id, $org->id);
    BackchannelAuthRequest::query()->update(['last_polled_at' => now()->subMinute()]);

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'urn:openid:params:grant-type:ciba',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'auth_req_id' => $result->authReqId,
    ])->assertOk();

    expect(orgRoleClaims($response->json('access_token'))['org_role'] ?? null)->toBe('viewer')
        ->and(orgRoleClaims($response->json('id_token'))['org_role'] ?? null)->toBe('viewer');
});

it('stamps the tier on an exchanged token', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Member);
    $registered = $this->makeClient(['api.read'], grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange', 'client_credentials']);
    $subjectToken = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['api.read'])->token;

    $response = $this->postJson('/oauth/token', [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
        'client_id' => $registered->client->client_id,
        'client_secret' => $registered->secret,
        'subject_token' => $subjectToken,
        'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
    ])->assertOk();

    expect(orgRoleClaims($response->json('access_token'))['org_role'] ?? null)->toBe('member');
});

it('carries no tier on a client-credentials token, nor on a token with no organization', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['api.read']);
    $registered->client->forceFill(['organization_id' => $org->id])->save();

    expect(orgRoleClaims(app(TokenIssuer::class)->issueClientCredentials($registered->client->refresh())->token))
        ->not->toHaveKey('org_role');

    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Owner);

    expect(orgRoleClaims(app(TokenIssuer::class)->issueForUser($registered->client, 'alice', null, ['api.read'])->token))
        ->not->toHaveKey('org_role');
});

it('carries no tier for a subject who is not an active member', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['openid']);
    $issuer = app(TokenIssuer::class);

    // No membership at all.
    expect(orgRoleClaims($issuer->issueForUser($registered->client, 'stranger', $org->id, ['openid'])->token))
        ->not->toHaveKey('org_role');

    // A suspended owner is not an owner to a relying party.
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Owner);
    app(TenantContext::class)->runAs(GenericTenant::of($org->id), fn () => Membership::query()
        ->where('user_id', 'alice')->update(['status' => MembershipStatus::Suspended->value]));

    $token = $issuer->issueForUser($registered->client, 'alice', $org->id, ['openid'])->token;

    expect(orgRoleClaims($token))->not->toHaveKey('org_role');

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonMissingPath('org_role');
});

it('reads UserInfo live, so a tier change shows without a new token', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Member);
    $registered = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['openid'])->token;

    app(Memberships::class)->changeRole($org->id, 'alice', MembershipRole::Admin);

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonPath('org_role', 'admin');
});

it('does not let a token-minting hook forge the tier', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Viewer);
    $registered = $this->makeClient(['openid']);

    app()->instance(ActionPipeline::class, new class implements ActionPipeline
    {
        public function run(HookPoint $hookPoint, ActionContext $context): PipelineOutcome
        {
            return PipelineOutcome::allow(['org_role' => 'owner', 'custom' => 'kept']);
        }
    });
    app()->forgetInstance(TokenIssuer::class);

    $claims = orgRoleClaims(app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['openid'])->token);

    expect($claims['org_role'] ?? null)->toBe('viewer')
        ->and($claims['custom'] ?? null)->toBe('kept');
});

it('advertises the claim in discovery', function (): void {
    $this->getJson('/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('claims_supported', fn (array $claims): bool => in_array('org_role', $claims, true));
});
