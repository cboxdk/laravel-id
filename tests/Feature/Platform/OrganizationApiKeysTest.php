<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Platform\Contracts\OrganizationApiKeys;
use Cbox\Id\Platform\PlatformRoot;
use Cbox\Id\Platform\TenantProvisioner;
use Cbox\Id\Platform\ValueObjects\TenantBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * The keys that drive the management API, held by the ORGANIZATION that owns the products
 * they act on.
 *
 * EVERY TEST HERE RUNS IN THE PLATFORM ROOT, and that is the point rather than boilerplate.
 * `organizations` is environment-owned; `resolve()` has to read the owner's status to
 * refuse a suspended customer's keys, and asked from a tenant host the deny-by-default
 * scope answers "no such organization" — which reads as "not active" and would refuse every
 * valid key on every host but one. Silently, and only in production, because a test that
 * never leaves the root cannot see it. The account plane never had this problem: `accounts`
 * sat outside tenancy, so the expression resolved from anywhere.
 */
function keyedOrganization(string $name = 'Acme'): string
{
    platformRootEnvironment();

    return app(TenantProvisioner::class)->provision(new TenantBlueprint(
        organizationName: $name,
        ownerEmail: strtolower($name).'@test.test',
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->organization->id;
}

/**
 * @template TReturn
 *
 * @param  Closure(): TReturn  $callback
 * @return TReturn
 */
function inRoot(Closure $callback): mixed
{
    return app(PlatformRoot::class)->run($callback);
}

it('issues a key, returns the plaintext once, and stores only its hash', function (): void {
    $organizationId = keyedOrganization();

    $issued = inRoot(fn () => app(OrganizationApiKeys::class)
        ->issue($organizationId, 'CI deploy', MembershipRole::Admin));

    expect($issued->plaintext)->toStartWith('cbid_org_')
        ->and($issued->key->role)->toBe(MembershipRole::Admin)
        ->and($issued->key->prefix)->toBe(substr($issued->plaintext, 0, 12))
        // Plaintext is never persisted — only its hash.
        ->and($issued->key->token_hash)->toBe(hash('sha256', $issued->plaintext))
        ->and($issued->key->getAttributes())->not->toContain($issued->plaintext);
});

it('resolves a valid token to its key and records use', function (): void {
    $keys = app(OrganizationApiKeys::class);
    $organizationId = keyedOrganization();
    $issued = inRoot(fn () => $keys->issue($organizationId, 'Key', MembershipRole::Developer));

    $resolved = $keys->resolve($issued->plaintext);

    expect($resolved)->not->toBeNull()
        ->and($resolved->id)->toBe($issued->key->id)
        ->and($resolved->last_used_at)->not->toBeNull();
});

it('rejects a valid key once its organization is suspended, and takes it back on reactivation', function (): void {
    $keys = app(OrganizationApiKeys::class);
    $organizationId = keyedOrganization();
    $issued = inRoot(fn () => $keys->issue($organizationId, 'Key', MembershipRole::Admin));

    expect($keys->resolve($issued->plaintext))->not->toBeNull();

    // The platform's off-switch: suspending the customer kills their keys immediately.
    inRoot(fn () => app(Organizations::class)->suspend($organizationId, 'op_test'));
    expect($keys->resolve($issued->plaintext))->toBeNull();

    inRoot(fn () => app(Organizations::class)->reactivate($organizationId, 'op_test'));
    expect($keys->resolve($issued->plaintext))->not->toBeNull();
})->group('security');

it('rejects a valid key once its organization is archived', function (): void {
    $keys = app(OrganizationApiKeys::class);
    $organizationId = keyedOrganization();
    $issued = inRoot(fn () => $keys->issue($organizationId, 'Key', MembershipRole::Admin));

    expect($keys->resolve($issued->plaintext))->not->toBeNull();

    // `Deleted`, the third case — and the one a gate written as `!== Suspended` lets
    // through. The account plane's status enum had two cases, so its `isActive()` could not
    // get this wrong; this one can, which is why the check asks `revokesAccess()`.
    inRoot(fn () => app(Organizations::class)->archive($organizationId, 'op_test'));

    expect($keys->resolve($issued->plaintext))->toBeNull();
})->group('security');

it('rejects unknown, revoked, and expired tokens', function (): void {
    $keys = app(OrganizationApiKeys::class);
    $organizationId = keyedOrganization();

    // Wrong-shape (no prefix) and right-prefix-but-unknown both resolve to null.
    expect($keys->resolve('bearer-nonsense'))->toBeNull()
        ->and($keys->resolve('cbid_org_notarealtoken'))->toBeNull();

    // Revoked.
    $revoked = inRoot(fn () => $keys->issue($organizationId, 'Revoked', MembershipRole::Admin));
    $keys->revoke($revoked->key->id);
    expect($keys->resolve($revoked->plaintext))->toBeNull();

    // Expired.
    $expired = inRoot(fn () => $keys->issue($organizationId, 'Expired', MembershipRole::Admin, now()->subMinute()));
    expect($keys->resolve($expired->plaintext))->toBeNull();
})->group('security');

it('lists an organization\'s keys newest first', function (): void {
    $keys = app(OrganizationApiKeys::class);
    $organizationId = keyedOrganization();

    inRoot(function () use ($keys, $organizationId): void {
        $keys->issue($organizationId, 'First', MembershipRole::Viewer);
        $keys->issue($organizationId, 'Second', MembershipRole::Admin);
    });

    // Another organization's key must not leak in.
    $other = keyedOrganization('Globex');
    inRoot(fn () => $keys->issue($other, 'Foreign', MembershipRole::Admin));

    $list = $keys->forOrganization($organizationId);

    expect($list)->toHaveCount(2)
        ->and($list->pluck('name')->all())->toBe(['Second', 'First']);
})->group('security');
