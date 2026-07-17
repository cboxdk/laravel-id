<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\InvalidManifest;
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

it('honours tenant_assignable, defaulting to true and marking opted-out permissions internal', function (): void {
    syncManifest('app_billing', [
        'version' => 'v1',
        'permissions' => [
            ['key' => 'invoices:read', 'description' => 'View invoices'],                                    // default → assignable
            ['key' => 'ledger:close', 'description' => 'Close the ledger', 'tenant_assignable' => false],    // internal, app-only
        ],
        'roles' => [],
    ]);

    expect(Permission::query()->where('name', 'invoices:read')->sole()->tenant_assignable)->toBeTrue()
        ->and(Permission::query()->where('name', 'ledger:close')->sole()->tenant_assignable)->toBeFalse();
});
