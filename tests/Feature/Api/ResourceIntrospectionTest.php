<?php

declare(strict_types=1);

use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Enums\OrganizationStatus;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// Token issuance requires an existing, active subject, not just an opaque fixture id.
beforeEach(function (): void {
    User::query()->create(['id' => 'user-one', 'email' => 'user-one@tokens.test', 'status' => UserStatus::Active]);
});

beforeEach(function (): void {
    $this->resource = 'https://domains.example.test/api';
    $this->makeApi($this->resource, ['domains:read']);
    $this->product = $this->makeClient(['domains:read']);
    $this->server = $this->makeClient();
    $this->org = $this->makeOrganization();
    $this->membership = app(Memberships::class)->add($this->org->id, 'user-one', MembershipRole::Admin);
    $this->issued = app(TokenIssuer::class)->issueForUser(
        $this->product->client, 'user-one', $this->org->id, ['domains:read'], $this->resource,
    );
    $this->requestBody = [
        'token' => $this->issued->token,
        'client_id' => $this->server->client->client_id,
        'client_secret' => $this->server->secret,
    ];
    config(['cbox-id.oauth.introspection.resource_servers' => [
        $this->server->client->client_id => [$this->resource],
    ]]);
});

it('permits only the explicitly granted resource server to introspect another clients token', function (): void {
    $this->postJson('/oauth/introspect', $this->requestBody)
        ->assertOk()->assertJsonPath('active', true)
        ->assertJsonPath('sub', 'user-one')
        ->assertJsonPath('client_id', $this->product->client->client_id)
        ->assertJsonPath('aud', $this->resource);
});

it('defaults to own tokens only', function (): void {
    config(['cbox-id.oauth.introspection.resource_servers' => []]);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
    $this->postJson('/oauth/introspect', array_replace($this->requestBody, [
        'client_id' => $this->product->client->client_id, 'client_secret' => $this->product->secret,
    ]))->assertJsonPath('active', true);
});

it('does not lend another clients grant to an unrelated caller', function (): void {
    $other = $this->makeClient();
    $this->postJson('/oauth/introspect', array_replace($this->requestBody, [
        'client_id' => $other->client->client_id, 'client_secret' => $other->secret,
    ]))->assertExactJson(['active' => false]);
});

it('requires an exact audience without prefix or wildcard matching', function (): void {
    config(['cbox-id.oauth.introspection.resource_servers' => [
        $this->server->client->client_id => ['https://domains.example.test/*', 'https://domains.example.test'],
    ]]);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
});

it('does not accept issuer audience even if it was configured accidentally', function (): void {
    $token = app(TokenIssuer::class)->issueForUser($this->product->client, 'user-one', $this->org->id);
    $issuer = app(IssuerResolver::class)->issuer();
    config(['cbox-id.oauth.introspection.resource_servers' => [$this->server->client->client_id => [$issuer]]]);
    $this->postJson('/oauth/introspect', array_replace($this->requestBody, ['token' => $token->token]))
        ->assertExactJson(['active' => false]);
});

it('does not expose revoked tokens to a granted resource server', function (): void {
    app(TokenIntrospector::class)->revoke($this->issued->jti);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
});

it('observes membership removal immediately', function (): void {
    $this->postJson('/oauth/introspect', $this->requestBody)->assertJsonPath('active', true);
    app(Memberships::class)->remove($this->org->id, 'user-one');
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
});

it('observes membership suspension immediately', function (): void {
    $this->membership->update(['status' => MembershipStatus::Suspended]);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
});

it('does not expose suspended organization tokens', function (): void {
    $this->org->update(['status' => OrganizationStatus::Suspended]);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
});

it('bounds organization owned resource callers even with an audience grant', function (): void {
    $otherOrg = $this->makeOrganization('Another customer');
    $this->server->client->update(['organization_id' => $otherOrg->id]);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
});

it('removes the resource grant immediately without revoking the original client token', function (): void {
    $this->postJson('/oauth/introspect', $this->requestBody)->assertJsonPath('active', true);
    config(['cbox-id.oauth.introspection.resource_servers' => []]);
    $this->postJson('/oauth/introspect', $this->requestBody)->assertExactJson(['active' => false]);
    expect(app(TokenIntrospector::class)->introspect($this->issued->token)->active)->toBeTrue();
});

it('does not let a resource grant cross the environment boundary', function (): void {
    $other = Environment::query()->create([
        'name' => 'Other environment', 'slug' => 'other-resource-test', 'type' => 'sandbox', 'status' => 'active',
    ]);
    $foreign = app(EnvironmentContext::class)->runAs($other, function (): string {
        $this->makeApi($this->resource, ['domains:read']);
        $client = $this->makeClient(['domains:read']);

        return app(TokenIssuer::class)->issueClientCredentials($client->client, ['domains:read'], $this->resource)->token;
    });
    $this->postJson('/oauth/introspect', array_replace($this->requestBody, ['token' => $foreign]))
        ->assertExactJson(['active' => false]);
});
