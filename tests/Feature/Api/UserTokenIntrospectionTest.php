<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * @return array{0: string, 1: string} [user token plaintext, env key plaintext]
 */
function introspectionFixture(TokenScope $scope = TokenScope::Write): array
{
    $org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme',
        slug: 'acme-'.Str::lower(Str::random(6)),
        type: OrganizationType::Customer,
    ));

    app(Memberships::class)->add($org->id, 'user_rp', 'admin');
    $token = app(UserApiTokens::class)->issue($org->id, 'user_rp', 'RP token', $scope, ['services']);

    $key = app(EnvironmentApiKeys::class)->issue('env_test', 'cortex-rp', EnvironmentApiScope::all());

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
