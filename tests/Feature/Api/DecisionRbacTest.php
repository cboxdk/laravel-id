<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/*
 * `POST /oauth/decisions` in RBAC mode: "may X do `feature:action` in org T", answered for
 * the calling app from the same resolver its tokens' `permissions` claim is stamped from.
 */

/** Declare the app's billing permissions and give `$userId` its billing-admin role in `$org`. */
function grantBillingAdmin(Client $client, string $organizationId, string $userId): void
{
    app(AppManifests::class)->sync($client->client_id, app(ManifestParser::class)->parse([
        'version' => '1',
        'permissions' => [
            ['key' => 'invoices:read', 'description' => null],
            ['key' => 'invoices:approve', 'description' => null],
            ['key' => 'invoices:delete', 'description' => null],
        ],
        'roles' => [
            ['key' => 'billing-admin', 'name' => 'Billing Admin', 'permissions' => ['invoices:read', 'invoices:approve']],
        ],
    ]));

    $role = Role::query()->where('client_id', $client->client_id)->where('key', 'billing-admin')->firstOrFail();
    app(Roles::class)->assign($organizationId, $userId, $role->id);
}

function rbacAsk(object $test, string $token, array $body): TestResponse
{
    return $test->postJson('/oauth/decisions', $body, ['Authorization' => 'Bearer '.$token]);
}

// ---------------------------------------------------------------- a person asking about themselves

it('answers a user token about its own permissions in its own organization', function (): void {
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Admin);
    $app = $this->makeClient(['openid']);
    grantBillingAdmin($app->client, $org->id, 'alice');
    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', $org->id, ['openid'])->token;

    rbacAsk($this, $token, ['permission' => ['invoices:approve', 'invoices:delete']])
        ->assertOk()
        ->assertJsonPath('mode', 'rbac')
        ->assertJsonPath('subject.id', 'alice')
        ->assertJsonPath('organization', $org->id)
        ->assertJsonPath('client_id', $app->client->client_id)
        ->assertJsonPath('org_role', 'admin')
        ->assertJsonPath('organization_active', true)
        ->assertJsonPath('results.0', ['permission' => 'invoices:approve', 'allowed' => true])
        ->assertJsonPath('results.1', ['permission' => 'invoices:delete', 'allowed' => false])
        // Every requested permission must be held for the whole answer to be yes.
        ->assertJsonPath('allowed', false);

    rbacAsk($this, $token, ['permission' => 'invoices:read'])
        ->assertOk()
        ->assertJsonPath('allowed', true)
        ->assertJsonCount(1, 'results');
});

it('answers for the calling app only — another app\'s role does not count', function (): void {
    $org = $this->makeOrganization();
    $billing = $this->makeClient(['openid']);
    $other = $this->makeClient(['openid']);
    grantBillingAdmin($billing->client, $org->id, 'alice');

    $token = app(TokenIssuer::class)->issueForUser($other->client, 'alice', $org->id, ['openid'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:approve'])
        ->assertOk()
        ->assertJsonPath('allowed', false);
});

it('rolls a grant in a parent organization down to its children', function (): void {
    $parent = $this->makeOrganization('Reseller');
    $child = $this->makeOrganization('Customer', parentId: $parent->id);
    $app = $this->makeClient(['openid']);
    grantBillingAdmin($app->client, $parent->id, 'alice');

    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', $child->id, ['openid'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:approve'])
        ->assertOk()
        ->assertJsonPath('organization', $child->id)
        ->assertJsonPath('allowed', true);
});

it('counts an environment-wide grant, with or without an organization', function (): void {
    $org = $this->makeOrganization();
    $app = $this->makeClient(['openid']);
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support');
    $roles->grantPermission(null, $support->id, 'tickets:read');
    $roles->assignEverywhere('agent', $support->id);

    $inOrg = app(TokenIssuer::class)->issueForUser($app->client, 'agent', $org->id, ['openid'])->token;
    $noOrg = app(TokenIssuer::class)->issueForUser($app->client, 'agent', null, ['openid'])->token;

    rbacAsk($this, $inOrg, ['permission' => 'tickets:read'])
        ->assertOk()
        ->assertJsonPath('allowed', true)
        // A grant everywhere is not a membership.
        ->assertJsonPath('org_role', null);

    rbacAsk($this, $noOrg, ['permission' => 'tickets:read'])
        ->assertOk()
        ->assertJsonPath('organization', null)
        ->assertJsonPath('allowed', true);
});

it('reflects a revoked role on the next call, with the same token', function (): void {
    $org = $this->makeOrganization();
    $app = $this->makeClient(['openid']);
    grantBillingAdmin($app->client, $org->id, 'alice');
    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', $org->id, ['openid'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:approve'])->assertJsonPath('allowed', true);

    app(Roles::class)->unassignAll($org->id, 'alice');

    rbacAsk($this, $token, ['permission' => 'invoices:approve'])->assertJsonPath('allowed', false);
});

it('denies everything in a suspended organization', function (): void {
    $org = $this->makeOrganization();
    $app = $this->makeClient(['openid']);
    grantBillingAdmin($app->client, $org->id, 'alice');
    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', $org->id, ['openid'])->token;

    app(Organizations::class)->suspend($org->id, 'operator');

    rbacAsk($this, $token, ['permission' => 'invoices:read'])
        ->assertOk()
        ->assertJsonPath('organization_active', false)
        ->assertJsonPath('results.0.allowed', false)
        ->assertJsonPath('allowed', false);
});

it('refuses a user token asking about somebody else, or another organization', function (): void {
    $org = $this->makeOrganization();
    $other = $this->makeOrganization();
    $app = $this->makeClient(['openid']);
    grantBillingAdmin($app->client, $org->id, 'bob');
    grantBillingAdmin($app->client, $other->id, 'alice');
    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', $org->id, ['openid'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:read', 'subject' => 'bob'])
        ->assertStatus(403)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonPath('error_description', 'a user token may only ask about its own subject');

    rbacAsk($this, $token, ['permission' => 'invoices:read', 'org' => $other->id])
        ->assertStatus(403)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonPath('error_description', 'a user token may only ask about the organization it was issued for');

    // Naming itself and its own organization is fine.
    rbacAsk($this, $token, ['permission' => 'invoices:read', 'subject' => 'alice', 'org' => $org->id])->assertOk();
});

// ---------------------------------------------------------------- an app asking about a person

it('answers an app\'s client token about any subject it names', function (): void {
    $org = $this->makeOrganization();
    $app = $this->makeClient(['decisions:read']);
    grantBillingAdmin($app->client, $org->id, 'alice');
    app(Memberships::class)->add($org->id, 'alice', MembershipRole::Member);
    $token = app(TokenIssuer::class)->issueClientCredentials($app->client, ['decisions:read'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:approve', 'subject' => 'alice', 'org' => $org->id])
        ->assertOk()
        ->assertJsonPath('subject', ['type' => 'user', 'id' => 'alice'])
        ->assertJsonPath('org_role', 'member')
        ->assertJsonPath('allowed', true);
});

it('requires decisions:read and a subject from a client token', function (): void {
    $org = $this->makeOrganization();
    $app = $this->makeClient(['api.read', 'decisions:read']);

    $unscoped = app(TokenIssuer::class)->issueClientCredentials($app->client, ['api.read'])->token;
    rbacAsk($this, $unscoped, ['permission' => 'invoices:read', 'subject' => 'alice', 'org' => $org->id])
        ->assertStatus(403)
        ->assertJsonPath('error', 'insufficient_scope');

    $scoped = app(TokenIssuer::class)->issueClientCredentials($app->client, ['decisions:read'])->token;
    rbacAsk($this, $scoped, ['permission' => 'invoices:read', 'org' => $org->id])
        ->assertStatus(422)
        ->assertJsonPath('error', 'invalid_request')
        ->assertJsonPath('error_description', '`subject` is required when the access token belongs to a client');
});

it('keeps a client an organization owns to that organization', function (): void {
    // A tenant-registered app must not be able to probe who holds what in other tenants.
    $mine = $this->makeOrganization('Mine');
    $theirs = $this->makeOrganization('Theirs');
    $app = $this->makeClient(['decisions:read']);
    $app->client->forceFill(['organization_id' => $mine->id])->save();
    grantBillingAdmin($app->client, $theirs->id, 'victim');
    $token = app(TokenIssuer::class)->issueClientCredentials($app->client->refresh(), ['decisions:read'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:read', 'subject' => 'victim', 'org' => $theirs->id])
        ->assertStatus(403)
        ->assertJsonPath('error', 'access_denied')
        ->assertJsonPath('error_description', 'this client may only ask about its own organization');

    // ...nor environment-wide, which would include grants that apply in every tenant.
    rbacAsk($this, $token, ['permission' => 'invoices:read', 'subject' => 'victim'])
        ->assertStatus(403)
        ->assertJsonPath('error', 'access_denied');

    rbacAsk($this, $token, ['permission' => 'invoices:read', 'subject' => 'victim', 'org' => $mine->id])->assertOk();
});

// ---------------------------------------------------------------- the request itself

it('refuses to mix RBAC and ReBAC checks in one request', function (): void {
    $app = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', 'org_x', ['openid'])->token;

    rbacAsk($this, $token, ['permission' => 'invoices:read', 'entitlements' => ['plan']])
        ->assertStatus(422)
        ->assertJsonPath('error', 'invalid_request');
});

it('refuses an empty or malformed permission, and bounds the batch', function (): void {
    $app = $this->makeClient(['openid']);
    $token = app(TokenIssuer::class)->issueForUser($app->client, 'alice', 'org_x', ['openid'])->token;

    rbacAsk($this, $token, ['permission' => ''])->assertStatus(422)->assertJsonPath('error', 'invalid_request');
    rbacAsk($this, $token, ['permission' => []])->assertStatus(422)->assertJsonPath('error', 'invalid_request');
    rbacAsk($this, $token, ['permission' => [['nested']]])->assertStatus(422)->assertJsonPath('error', 'invalid_request');

    config(['cbox-id.oauth.decisions.max_batch' => 2]);

    rbacAsk($this, $token, ['permission' => ['a:read', 'b:read', 'c:read']])
        ->assertStatus(422)
        ->assertJsonPath('error', 'batch_too_large');
});
