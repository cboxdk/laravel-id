<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * ROLES HELD EVERYWHERE, NOT INSIDE ONE TENANT.
 *
 * `role_assignments.organization_id` is NOT NULL, so until now a grant had to name a
 * tenant. That left three ordinary things unrepresentable: a support agent of the product
 * who acts across every customer, somebody who has joined no organization, and any
 * service provider with no tenancy of its own to hang a grant on. Each of them got a
 * token carrying no roles and no permissions, and there was no way to give them any.
 */
it('applies an environment-wide grant inside every organization', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    $roles->assignEverywhere('user-1', $support->id);

    // Two unrelated tenants. The grant was made against neither.
    foreach (['org-a', 'org-b'] as $organizationId) {
        expect(app(AccessChecker::class)->forToken('user-1', $organizationId, 'cid_any')->roles)
            ->toBe(['Support']);
    }
});

/**
 * The case the whole thing exists for: no organization at all.
 */
it('carries environment-wide roles for somebody who belongs to no organization', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    // attachPermission(), not grantPermission(): the latter matches the role on
    // `organization_id` and so can never reach an environment-wide one. Null names the
    // environment plane, which is where this role lives.
    $permission = Permission::query()->create(['name' => 'tickets.read', 'tenant_assignable' => true]);
    $roles->attachPermission($support->id, $permission->id, null);

    $roles->assignEverywhere('user-1', $support->id);

    $claims = app(AccessChecker::class)->forToken('user-1', null, 'cid_any');

    expect($claims->roles)->toBe(['Support'])
        ->and($claims->permissions)->toBe(['tickets.read']);
});

/**
 * @group security
 *
 * THE ONE GUARD THAT IS NOT MERELY TIDY.
 *
 * A role owned by one organization is that tenant's own policy — named by them, meaning
 * what they say it means. Handing it out across the whole environment would grant every
 * other tenant a role they did not define and cannot see, under a name they never chose.
 */
it('refuses to grant one organization’s role across the environment', function (): void {
    $roles = app(Roles::class);

    $theirs = $roles->define('org-a', 'Billing admin');

    expect(fn () => $roles->assignEverywhere('user-1', $theirs->id))
        ->toThrow(UnknownRole::class);

    expect(app(AccessChecker::class)->forToken('user-1', 'org-b', 'cid_any')->roles)->toBe([]);
})->group('security');

/**
 * And an app-declared role is refused for the same reason one step along: it belongs to
 * an application, and granting it everywhere would put another app's vocabulary into
 * every tenant.
 */
it('refuses to grant an app-declared role across the environment', function (): void {
    $roles = app(Roles::class);

    $client = app(ClientRegistry::class)->register(new NewClient('Reports', ClientType::Confidential))->client;
    $declared = $roles->define(null, 'Report viewer', null, $client->client_id);

    expect(fn () => $roles->assignEverywhere('user-1', $declared->id))
        ->toThrow(UnknownRole::class);
})->group('security');

/**
 * Both kinds of grant hold at once — an environment-wide role does not replace what
 * somebody holds in one organization, or the mix the whole design is for would collapse
 * into whichever was written last.
 */
it('unions an environment-wide grant with an organization one', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    $editor = $roles->define('org-a', 'Editor');

    $roles->assignEverywhere('user-1', $support->id);
    $roles->assign('org-a', 'user-1', $editor->id);

    expect(app(AccessChecker::class)->forToken('user-1', 'org-a', 'cid_any')->roles)
        ->toEqualCanonicalizing(['Support', 'Editor']);

    // …and only the environment-wide one reaches the tenant it was never granted in.
    expect(app(AccessChecker::class)->forToken('user-1', 'org-b', 'cid_any')->roles)
        ->toBe(['Support']);
});

it('takes an environment-wide grant back everywhere at once', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    $roles->assignEverywhere('user-1', $support->id);
    $roles->unassignEverywhere('user-1', $support->id);

    expect(app(AccessChecker::class)->forToken('user-1', 'org-a', 'cid_any')->roles)->toBe([]);
});

/**
 * Granting the same thing twice is one grant. The unique index says so on every engine,
 * which is the entire reason this is its own table rather than a nullable column: with a
 * NULL organization, Postgres and MySQL both treat the rows as distinct and firstOrCreate
 * would never match.
 */
it('is idempotent', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    $roles->assignEverywhere('user-1', $support->id);
    $roles->assignEverywhere('user-1', $support->id);

    expect($roles->everywhereFor('user-1'))->toBe([$support->id]);
});

/**
 * @group security
 *
 * Segregation of duties asks "what does this person effectively hold here". An
 * environment-wide grant that were invisible to it would let a toxic pair form across the
 * two kinds — the one combination nobody would think to look for.
 */
it('shows an environment-wide grant to the segregation-of-duties read', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    $editor = $roles->define('org-a', 'Editor');

    $roles->assignEverywhere('user-1', $support->id);
    $roles->assign('org-a', 'user-1', $editor->id);

    expect($roles->assignmentsForSubject('org-a', 'user-1'))
        ->toEqualCanonicalizing([$support->id, $editor->id]);
})->group('security');

/**
 * A global role with no permissions is a name and nothing else.
 *
 * `grantPermission()` took a non-nullable organization and matched the role on it, so the
 * one kind of role that can be granted across every tenant was the one kind this method
 * could never reach. The gap was invisible until environment-wide grants existed.
 */
it('grants a permission to an environment-wide role from the environment plane', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');
    $roles->grantPermission(null, $support->id, 'tickets.read');
    $roles->assignEverywhere('user-1', $support->id);

    expect(app(AccessChecker::class)->forToken('user-1', 'org-anywhere', 'cid_any')->permissions)
        ->toBe(['tickets.read']);
});

/**
 * And naming a tenant still refuses, which is the half that was already right: a tenant
 * may not attach policy to a role the whole environment holds.
 */
it('refuses to grant a permission to an environment-wide role in a tenant’s name', function (): void {
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support');

    expect(fn () => $roles->grantPermission('org-a', $support->id, 'tickets.read'))
        ->toThrow(UnknownRole::class);
})->group('security');
