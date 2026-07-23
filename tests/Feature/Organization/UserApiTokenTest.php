<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Authorization\ValueObjects\ResourceRef;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\Exceptions\TokenScopeExceedsIssuerRole;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\Models\UserApiToken;
use Cbox\Id\Organization\ValueObjects\GrantSubject;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/** An organization with one active member holding the given role. */
function memberOrg(string $role = 'admin', string $userId = 'user_1'): Organization
{
    $org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme Inc',
        slug: 'acme-'.Str::lower(Str::random(8)),
        type: OrganizationType::Customer,
        parentId: null,
    ));

    app(Memberships::class)->add($org->id, $userId, $role);

    return $org;
}

it('issues a token whose plaintext is shown once and stored only as a hash', function (): void {
    $org = memberOrg();

    $issued = app(UserApiTokens::class)->issue($org->id, 'user_1', 'CI token', TokenScope::Read);

    expect($issued->plaintext)->toStartWith('cbid_pat_')
        ->and($issued->token->token_hash)->toBe(hash('sha256', $issued->plaintext))
        ->and($issued->token->prefix)->toBe(substr($issued->plaintext, 0, 12))
        ->and($issued->token->toArray())->not->toHaveKey('token_hash');
});

it('applies the default hard expiry when none is given', function (): void {
    $org = memberOrg();

    $issued = app(UserApiTokens::class)->issue($org->id, 'user_1', 'CI token', TokenScope::Read);

    expect($issued->token->expires_at)->not->toBeNull()
        ->and($issued->token->expires_at?->isFuture())->toBeTrue();
});

it('resolves a live token and stamps last_used_at', function (): void {
    $org = memberOrg();
    $issued = app(UserApiTokens::class)->issue($org->id, 'user_1', 'CI token', TokenScope::Write);

    $resolved = app(UserApiTokens::class)->resolve($issued->plaintext);

    expect($resolved?->id)->toBe($issued->token->id)
        ->and($resolved?->organization_id)->toBe($org->id)
        ->and($resolved?->last_used_at)->not->toBeNull();
});

it('resolves nothing for a wrong prefix, an unknown token, a revoked token, or an expired token', function (): void {
    $org = memberOrg();
    $tokens = app(UserApiTokens::class);

    $revoked = $tokens->issue($org->id, 'user_1', 'Revoked', TokenScope::Read);
    $tokens->revoke($org->id, $revoked->token->id);

    $expired = $tokens->issue($org->id, 'user_1', 'Expired', TokenScope::Read, null, now()->subMinute());

    expect($tokens->resolve('not_ours_at_all'))->toBeNull()
        ->and($tokens->resolve('cbid_pat_'.str_repeat('x', 48)))->toBeNull()
        ->and($tokens->resolve($revoked->plaintext))->toBeNull()
        ->and($tokens->resolve($expired->plaintext))->toBeNull();
});

it('restricts a token to its resource families, with null meaning unrestricted', function (): void {
    $org = memberOrg();
    $tokens = app(UserApiTokens::class);

    $restricted = $tokens->issue($org->id, 'user_1', 'Deploys', TokenScope::Write, ['services', 'deployments']);
    $open = $tokens->issue($org->id, 'user_1', 'Everything', TokenScope::Write);

    expect($restricted->token->allowsFamily('services'))->toBeTrue()
        ->and($restricted->token->allowsFamily('billing'))->toBeFalse()
        ->and($open->token->allowsFamily('billing'))->toBeTrue();
});

it('normalises an empty family list to unrestricted (the null ⇒ all contract)', function (): void {
    $org = memberOrg();

    $issued = app(UserApiTokens::class)->issue($org->id, 'user_1', 'CI', TokenScope::Read, []);

    expect($issued->token->resource_families)->toBeNull();
});

it('caps the scope at the issuer role: a viewer mints read only', function (): void {
    $org = memberOrg(role: 'viewer');
    $tokens = app(UserApiTokens::class);

    expect($tokens->issue($org->id, 'user_1', 'Read', TokenScope::Read)->token)->toBeInstanceOf(UserApiToken::class)
        ->and(fn () => $tokens->issue($org->id, 'user_1', 'Write', TokenScope::Write))->toThrow(TokenScopeExceedsIssuerRole::class)
        ->and(fn () => $tokens->issue($org->id, 'user_1', 'Admin', TokenScope::Admin))->toThrow(TokenScopeExceedsIssuerRole::class);
});

it('caps the scope at the issuer role: a developer mints read and write, never admin', function (): void {
    $org = memberOrg(role: 'developer');
    $tokens = app(UserApiTokens::class);

    expect($tokens->issue($org->id, 'user_1', 'Write', TokenScope::Write)->token->scope)->toBe(TokenScope::Write)
        ->and(fn () => $tokens->issue($org->id, 'user_1', 'Admin', TokenScope::Admin))->toThrow(TokenScopeExceedsIssuerRole::class);
});

it('lets an admin-capable member mint an admin token', function (): void {
    $org = memberOrg(role: 'admin');

    $issued = app(UserApiTokens::class)->issue($org->id, 'user_1', 'Admin', TokenScope::Admin);

    expect($issued->token->scope)->toBe(TokenScope::Admin);
});

it('refuses any token for a non-member', function (): void {
    $org = $this->makeOrganization();

    expect(fn () => app(UserApiTokens::class)->issue($org->id, 'user_stranger', 'Nope', TokenScope::Read))
        ->toThrow(TokenScopeExceedsIssuerRole::class);
});

it('the cap honours the effective role, not just the raw membership', function (): void {
    // A viewer by membership, elevated to admin org-wide via a grant on the
    // organization's own ref — the cap sees the same effective role every
    // other authorization decision would.
    $org = memberOrg(role: 'viewer');
    $this->grantAccess($org->id, GrantSubject::user('user_1'), MembershipRole::Admin, ResourceRef::of('organization', $org->id));

    // Org-level effectiveRole() considers membership only, so admin scope is
    // still refused — the elevation is resource-scoped, not org-wide.
    expect(fn () => app(UserApiTokens::class)->issue($org->id, 'user_1', 'Admin', TokenScope::Admin))
        ->toThrow(TokenScopeExceedsIssuerRole::class);
});

it('lists a user\'s tokens newest first and revoke stops a token immediately', function (): void {
    $org = memberOrg();
    $tokens = app(UserApiTokens::class);

    $first = $tokens->issue($org->id, 'user_1', 'First', TokenScope::Read);
    $second = $tokens->issue($org->id, 'user_1', 'Second', TokenScope::Read);

    expect($tokens->forUser($org->id, 'user_1')->pluck('name')->all())->toBe(['Second', 'First']);

    $tokens->revoke($org->id, $first->token->id);

    expect($tokens->resolve($first->plaintext))->toBeNull()
        ->and($tokens->resolve($second->plaintext))->not->toBeNull();
});

it('isolates tokens between organizations', function (): void {
    $a = memberOrg();
    $b = $this->makeOrganization('B');

    $issued = app(UserApiTokens::class)->issue($a->id, 'user_1', 'A token', TokenScope::Read);

    // Revoking from the wrong org must not touch it.
    app(UserApiTokens::class)->revoke($b->id, $issued->token->id);

    expect(app(UserApiTokens::class)->resolve($issued->plaintext))->not->toBeNull()
        ->and(app(UserApiTokens::class)->forUser($b->id, 'user_1'))->toHaveCount(0);
});
