<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\InvalidManifest;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Manifest\ManifestSyncResult;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @return array<string, mixed>
 */
function billingManifest(): array
{
    return [
        'version' => '2026-07-01',
        'permissions' => [
            ['key' => 'invoices:create', 'description' => 'Create invoices'],
            ['key' => 'invoices:refund', 'description' => 'Refund invoices'],
            ['key' => 'invoices:read', 'description' => 'View invoices'],
        ],
        'roles' => [
            ['key' => 'billing-admin', 'name' => 'Billing Admin', 'permissions' => ['invoices:create', 'invoices:refund', 'invoices:read']],
            ['key' => 'viewer', 'name' => 'Viewer', 'permissions' => ['invoices:read']],
        ],
    ];
}

/**
 * @param  array<string, mixed>  $data
 */
function syncManifest(string $clientId, array $data): ManifestSyncResult
{
    return app(AppManifests::class)->sync($clientId, app(ManifestParser::class)->parse($data));
}

it('syncs an app manifest into declared roles and permissions', function (): void {
    $result = syncManifest('app_billing', billingManifest());

    expect($result->unchanged)->toBeFalse()
        ->and($result->rolesDeclared)->toBe(2)
        ->and($result->permissionsDeclared)->toBe(3);

    expect(Permission::query()->where('client_id', 'app_billing')->pluck('name')->all())
        ->toContain('invoices:create', 'invoices:refund', 'invoices:read');

    $admin = Role::query()->where('client_id', 'app_billing')->where('key', 'billing-admin')->first();
    expect($admin)->not->toBeNull()
        ->and($admin->name)->toBe('Billing Admin')
        ->and($admin->source->value)->toBe('manifest')
        ->and($admin->organization_id)->toBeNull();
});

it('is idempotent — an unchanged manifest is a no-op', function (): void {
    syncManifest('app_billing', billingManifest());
    $again = syncManifest('app_billing', billingManifest());

    expect($again->unchanged)->toBeTrue()
        ->and(Role::query()->where('client_id', 'app_billing')->count())->toBe(2)
        ->and(Permission::query()->where('client_id', 'app_billing')->count())->toBe(3);
});

it('grants an assigned app-declared role its permissions through the checker', function (): void {
    $org = $this->makeOrganization();
    syncManifest('app_billing', billingManifest());
    $admin = Role::query()->where('client_id', 'app_billing')->where('key', 'billing-admin')->firstOrFail();

    app(Roles::class)->assign($org->id, 'user_1', $admin->id);

    $checker = app(AccessChecker::class);
    expect($checker->can('user_1', 'invoices:refund', $org->id))->toBeTrue()
        ->and($checker->can('user_1', 'invoices:read', $org->id))->toBeTrue()
        ->and($checker->permissionsFor('user_1', $org->id))->toContain('invoices:create', 'invoices:refund', 'invoices:read');
});

it('keeps and flags an orphaned role instead of deleting it, preserving assignments', function (): void {
    $org = $this->makeOrganization();
    syncManifest('app_billing', billingManifest());
    $viewer = Role::query()->where('client_id', 'app_billing')->where('key', 'viewer')->firstOrFail();
    app(Roles::class)->assign($org->id, 'user_1', $viewer->id);

    // A later manifest drops the viewer role.
    $dropped = billingManifest();
    $dropped['roles'] = [$dropped['roles'][0]]; // keep only billing-admin
    $result = syncManifest('app_billing', $dropped);

    expect($result->orphanedRoleKeys)->toContain('viewer');

    $viewer->refresh();
    expect($viewer->orphaned_at)->not->toBeNull()                                    // kept, flagged
        ->and(RoleAssignment::query()->where('role_id', $viewer->id)->exists())->toBeTrue(); // assignment intact
});

it('re-declaring an orphaned role un-flags it', function (): void {
    syncManifest('app_billing', billingManifest());
    $dropped = billingManifest();
    $dropped['roles'] = [$dropped['roles'][0]];
    syncManifest('app_billing', $dropped);
    syncManifest('app_billing', billingManifest()); // viewer declared again

    $viewer = Role::query()->where('client_id', 'app_billing')->where('key', 'viewer')->firstOrFail();
    expect($viewer->orphaned_at)->toBeNull();
});

it('scopes declared catalogs per app', function (): void {
    syncManifest('app_billing', billingManifest());
    syncManifest('app_support', [
        'version' => '1',
        'permissions' => [['key' => 'tickets:close', 'description' => null]],
        'roles' => [['key' => 'agent', 'name' => 'Agent', 'permissions' => ['tickets:close']]],
    ]);

    expect(app(AppManifests::class)->declaredRoles('app_billing'))->toHaveCount(2)
        ->and(app(AppManifests::class)->declaredRoles('app_support'))->toHaveCount(1);

    // Two apps may declare a same-named permission without collision.
    syncManifest('app_support', [
        'version' => '2',
        'permissions' => [['key' => 'invoices:read', 'description' => 'Support view of invoices']],
        'roles' => [['key' => 'agent', 'name' => 'Agent', 'permissions' => ['invoices:read']]],
    ]);
    expect(Permission::query()->where('name', 'invoices:read')->count())->toBe(2);
});

it('rejects a malformed manifest whole', function (array $bad): void {
    expect(fn () => app(ManifestParser::class)->parse($bad))->toThrow(InvalidManifest::class);
})->with([
    'no version' => [['permissions' => [], 'roles' => []]],
    'bad permission key' => [['version' => '1', 'permissions' => [['key' => 'Invoices Create']], 'roles' => []]],
    'undeclared permission' => [['version' => '1', 'permissions' => [], 'roles' => [['key' => 'x', 'name' => 'X', 'permissions' => ['nope:read']]]]],
    'duplicate role name' => [['version' => '1', 'permissions' => [], 'roles' => [['key' => 'a', 'name' => 'Admin', 'permissions' => []], ['key' => 'b', 'name' => 'Admin', 'permissions' => []]]]],
]);

it('honours tenant_assignable opt-in, defaulting to internal (deny-by-default)', function (): void {
    syncManifest('app_billing', [
        'version' => 'v1',
        'permissions' => [
            ['key' => 'invoices:read', 'description' => 'View invoices', 'tenant_assignable' => true],       // explicit opt-in → assignable
            ['key' => 'ledger:close', 'description' => 'Close the ledger'],                                   // omitted → internal, app-only
            ['key' => 'ledger:void', 'description' => 'Void an entry', 'tenant_assignable' => false],         // explicit opt-out → internal
        ],
        'roles' => [],
    ]);

    // Deny-by-default: only an explicit `tenant_assignable: true` opts a permission into
    // tenant self-serve. An omitted field is internal, same as an explicit false — as
    // apps become third-party-authored, an unset field must not widen access.
    expect(Permission::query()->where('name', 'invoices:read')->sole()->tenant_assignable)->toBeTrue()
        ->and(Permission::query()->where('name', 'ledger:close')->sole()->tenant_assignable)->toBeFalse()
        ->and(Permission::query()->where('name', 'ledger:void')->sole()->tenant_assignable)->toBeFalse();
});

/**
 * A role the declaring app has retired must not be grantable, however the grant arrives.
 *
 * Orphaning keeps the row and its existing assignments — deleting them would revoke
 * access on a deploy blip — and the console stops OFFERING the role. But `assign()` did
 * not refuse it, so an administrator who knew a retired role's id could map a directory
 * group to it by calling the Livewire action directly, and every reconcile then granted a
 * role the owning application no longer believes in. Tokens carry it; nothing the app
 * ships understands it.
 *
 * A role that has vanished from the UI is exactly the one someone would name by hand.
 */
it('refuses to grant a role its declaring app has dropped', function (): void {
    $org = $this->makeOrganization();

    syncManifest('app_billing', billingManifest());
    $viewer = Role::query()->where('client_id', 'app_billing')->where('key', 'viewer')->firstOrFail();

    $dropped = billingManifest();
    $dropped['roles'] = [$dropped['roles'][0]];
    syncManifest('app_billing', $dropped);

    expect($viewer->refresh()->orphaned_at)->not->toBeNull();

    expect(fn () => app(Roles::class)->assign($org->id, 'user_new', $viewer->id))
        ->toThrow(UnknownRole::class);

    // Existing holders keep it — orphaning flags, it does not revoke.
    expect(Role::query()->whereKey($viewer->id)->exists())->toBeTrue();
});

/**
 * And re-declaring it makes it grantable again, so the refusal tracks the manifest rather
 * than being a one-way door.
 */
it('grants a re-declared role again', function (): void {
    $org = $this->makeOrganization();

    syncManifest('app_billing', billingManifest());
    $dropped = billingManifest();
    $dropped['roles'] = [$dropped['roles'][0]];
    syncManifest('app_billing', $dropped);
    syncManifest('app_billing', billingManifest());

    $viewer = Role::query()->where('client_id', 'app_billing')->where('key', 'viewer')->firstOrFail();

    app(Roles::class)->assign($org->id, 'user_rejoin', $viewer->id);

    expect(RoleAssignment::query()->where('role_id', $viewer->id)->where('user_id', 'user_rejoin')->exists())->toBeTrue();
});
