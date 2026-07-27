<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Organization\ValueObjects\ResourceFamilies;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * @param  list<string>|null  $keyScopes  the environment key's scopes; full access by default
 * @return array{0: string, 1: string} [user token plaintext, env key plaintext]
 */
function introspectionFixture(TokenScope $scope = TokenScope::Write, ?array $keyScopes = null): array
{
    $org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme',
        slug: 'acme-'.Str::lower(Str::random(6)),
        type: OrganizationType::Customer,
    ));

    app(Memberships::class)->add($org->id, 'user_rp', MembershipRole::Admin);
    $token = app(UserApiTokens::class)->issue($org->id, 'user_rp', 'RP token', $scope, ResourceFamilies::of('services'));

    $key = app(EnvironmentApiKeys::class)->issue('env_test', 'cortex-rp', $keyScopes ?? EnvironmentApiScope::all());

    return [$token->plaintext, $key->plaintext];
}

it('introspects an active user token for an authenticated relying party', function (): void {
    [$token, $key] = introspectionFixture();

    $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => $token])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('sub', 'user_rp')
        ->assertJsonPath('scope', 'write')
        ->assertJsonPath('families.0', 'services');
});

it('refuses unauthenticated callers — the endpoint is never an oracle', function (): void {
    [$token] = introspectionFixture();

    $this->postJson('/user-tokens/introspect', ['token' => $token])->assertStatus(401);
    $this->withToken('cbid_env_bogus')->postJson('/user-tokens/introspect', ['token' => $token])
        ->assertStatus(401);
});

it('answers active:false for unknown, revoked, and cross-environment tokens', function (): void {
    [$token, $key] = introspectionFixture();

    // Unknown token.
    $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => 'cbid_pat_'.str_repeat('x', 48)])
        ->assertOk()->assertJsonPath('active', false);

    // Revoked token.
    $tokens = app(UserApiTokens::class);
    $resolved = $tokens->resolve($token);
    expect($resolved)->not->toBeNull();
    $tokens->revoke($resolved->organization_id, $resolved->id);

    $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => $token])
        ->assertOk()->assertJsonPath('active', false);
});

/**
 * The privilege-escalation regression. Introspection discloses `sub`, `org` and
 * `name` for any personal access token in the environment, so it is user data and
 * needs `users:read` — the same scope that gates `GET /users`. Before this check a
 * key issued with nothing but `directories:read` could read back the identity
 * behind every token in the environment.
 */
it('refuses a caller whose key lacks users:read', function (): void {
    [$token, $key] = introspectionFixture(keyScopes: [EnvironmentApiScope::DirectoriesRead->value]);

    $response = $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => $token]);

    $response->assertStatus(403)
        ->assertJsonPath('error', 'insufficient_scope')
        ->assertJsonPath('scope', 'users:read')
        ->assertJsonMissingPath('sub')
        ->assertJsonMissingPath('active');

    expect($response->headers->get('WWW-Authenticate'))->toContain('insufficient_scope');
});

/**
 * 403, deliberately, not `active: false`. The refusal is decided before the token
 * is looked at, so it is a constant function of the CALLER's key and leaks nothing
 * about the token — while answering `active: false` would tell a relying party its
 * users' live credentials were all dead.
 */
it('answers the same 403 whether or not the token exists — the refusal is about the caller', function (): void {
    [$token, $key] = introspectionFixture(keyScopes: [EnvironmentApiScope::DirectoriesRead->value]);

    $known = $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => $token]);
    $unknown = $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => 'cbid_pat_'.str_repeat('x', 48)]);

    expect($unknown->status())->toBe($known->status())
        ->and($unknown->json())->toBe($known->json());
});

it('admits a caller carrying exactly users:read', function (): void {
    [$token, $key] = introspectionFixture(keyScopes: [EnvironmentApiScope::UsersRead->value]);

    $this->withToken($key)->postJson('/user-tokens/introspect', ['token' => $token])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('sub', 'user_rp');
});

it('reports a token restricted to no family as an empty list, not as unrestricted', function (): void {
    $org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme',
        slug: 'acme-'.Str::lower(Str::random(6)),
        type: OrganizationType::Customer,
    ));
    app(Memberships::class)->add($org->id, 'user_rp', MembershipRole::Admin);

    $token = app(UserApiTokens::class)->issue($org->id, 'user_rp', 'Nothing', TokenScope::Read, ResourceFamilies::none());
    $key = app(EnvironmentApiKeys::class)->issue('env_test', 'cortex-rp', EnvironmentApiScope::all());

    $this->withToken($key->plaintext)->postJson('/user-tokens/introspect', ['token' => $token->plaintext])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('families', []);
});
