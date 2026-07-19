<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
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
