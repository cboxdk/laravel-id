<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\Organization\Contracts\Memberships;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @return array<string, mixed>
 */
function claimsOf(string $jwt): array
{
    return (array) json_decode((string) JWT::urlsafeB64Decode(explode('.', $jwt)[1]), true);
}

function declareBilling(string $clientId): void
{
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
}

it('stamps app-scoped roles + permissions into a user token', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['openid']);
    declareBilling($registered->client->client_id);
    $role = Role::query()->where('client_id', $registered->client->client_id)->where('key', 'billing-admin')->firstOrFail();
    app(Roles::class)->assign($org->id, 'alice', $role->id);

    $claims = claimsOf(app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['openid'])->token);

    expect($claims['roles'])->toContain('billing-admin')
        ->and($claims['permissions'])->toContain('invoices:create', 'invoices:read');
});

it("does not leak one app's roles into another app's token", function (): void {
    $org = $this->makeOrganization();
    $billing = $this->makeClient(['openid']);
    $other = $this->makeClient(['openid']);
    declareBilling($billing->client->client_id);
    $role = Role::query()->where('client_id', $billing->client->client_id)->where('key', 'billing-admin')->firstOrFail();
    app(Roles::class)->assign($org->id, 'alice', $role->id);

    // A token for a DIFFERENT app: alice holds no role that app owns.
    $claims = claimsOf(app(TokenIssuer::class)->issueForUser($other->client, 'alice', $org->id, ['openid'])->token);

    expect($claims)->not->toHaveKey('roles')
        ->and($claims)->not->toHaveKey('permissions');
});

it('carries no roles claim on a client-credentials token', function (): void {
    $registered = $this->makeClient(['openid']);

    expect(claimsOf(app(TokenIssuer::class)->issueClientCredentials($registered->client, [])->token))
        ->not->toHaveKey('roles');
});

it('mirrors app-scoped roles + permissions on the UserInfo endpoint', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['openid']);
    declareBilling($registered->client->client_id);
    $role = Role::query()->where('client_id', $registered->client->client_id)->where('key', 'billing-admin')->firstOrFail();
    app(Roles::class)->assign($org->id, 'alice', $role->id);

    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['openid'])->token;

    // The standard RP login flow reads id_token + UserInfo — the same RBAC signal
    // the JWT carries must be available here, scoped to this app.
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonPath('org', $org->id)
        ->assertJsonPath('roles', ['billing-admin'])
        ->assertJsonPath('permissions.0', 'invoices:create');
});

it('omits the RBAC claims from UserInfo when the user holds no roles for the app', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['openid']);

    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['openid'])->token;

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonMissingPath('roles');
});

it("does not leak one app's roles into another app's UserInfo response", function (): void {
    // Cross-app isolation on the UserInfo path (the JWT path is covered above): alice
    // holds billing-admin in app A; app B's token must never surface it.
    $org = $this->makeOrganization();
    $appA = $this->makeClient(['openid']);
    $appB = $this->makeClient(['openid']);
    declareBilling($appA->client->client_id);
    $role = Role::query()->where('client_id', $appA->client->client_id)->where('key', 'billing-admin')->firstOrFail();
    app(Roles::class)->assign($org->id, 'alice', $role->id);

    $tokenB = app(TokenIssuer::class)->issueForUser($appB->client, 'alice', $org->id, ['openid'])->token;

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokenB])
        ->assertOk()
        ->assertJsonMissingPath('roles')
        ->assertJsonMissingPath('permissions');
});

it('lists the subject active organizations on UserInfo when the organizations scope is granted', function (): void {
    $orgA = $this->makeOrganization();
    $orgB = $this->makeOrganization();
    app(Memberships::class)->add($orgA->id, 'alice', 'admin');
    app(Memberships::class)->add($orgB->id, 'alice', 'member');

    $registered = $this->makeClient(['openid', 'organizations']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $orgA->id, ['openid', 'organizations'])->token;

    $response = $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonCount(2, 'organizations');

    $orgs = collect($response->json('organizations'))->keyBy('id');
    expect($orgs[$orgA->id]['name'])->toBe($orgA->name)
        ->and($orgs[$orgA->id]['role'])->toBe('admin')
        ->and($orgs[$orgB->id]['role'])->toBe('member');
});

it('does NOT leak organizations on a plain profile login (least disclosure)', function (): void {
    // The org list spans unrelated customers/apps, so a profile-scoped login must not
    // expose it — only a client that explicitly requests `organizations` gets it.
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', 'admin');

    $registered = $this->makeClient(['openid', 'profile']);
    $token = app(TokenIssuer::class)->issueForUser($registered->client, 'alice', $org->id, ['openid', 'profile'])->token;

    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$token])
        ->assertOk()
        ->assertJsonMissingPath('organizations');
});
