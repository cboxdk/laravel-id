<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\Permission;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('grants a permission through a role assignment', function (): void {
    $org = $this->makeOrganization();
    $this->grantRole('user_1', $org->id, 'admin', ['members.invite', 'billing.read']);

    $checker = app(AccessChecker::class);

    expect($checker->can('user_1', 'members.invite', $org->id))->toBeTrue()
        ->and($checker->can('user_1', 'billing.read', $org->id))->toBeTrue();
});

it('denies by default', function (): void {
    $org = $this->makeOrganization();
    $this->grantRole('user_1', $org->id, 'member', ['docs.read']);

    $checker = app(AccessChecker::class);

    expect($checker->can('user_1', 'billing.read', $org->id))->toBeFalse()   // permission not granted
        ->and($checker->can('user_2', 'docs.read', $org->id))->toBeFalse();   // user not assigned
});

it('lists a user\'s effective permissions', function (): void {
    $org = $this->makeOrganization();
    $this->grantRole('user_1', $org->id, 'admin', ['a', 'b']);

    expect(app(AccessChecker::class)->permissionsFor('user_1', $org->id))
        ->toContain('a', 'b')
        ->toHaveCount(2);
});

it('rolls roles down from an ancestor org (reseller management)', function (): void {
    $reseller = $this->makeOrganization('Reseller');
    $customer = $this->makeOrganization('Customer', parentId: $reseller->id);

    // A support role granted at the reseller applies to the customer beneath it.
    $this->grantRole('support_1', $reseller->id, 'support', ['tickets.manage']);

    $checker = app(AccessChecker::class);

    expect($checker->can('support_1', 'tickets.manage', $customer->id))->toBeTrue()
        ->and($checker->can('support_1', 'tickets.manage', $reseller->id))->toBeTrue();
});

it('does not leak roles upward or sideways', function (): void {
    $reseller = $this->makeOrganization('Reseller');
    $customer = $this->makeOrganization('Customer', parentId: $reseller->id);
    $other = $this->makeOrganization('Other');

    $this->grantRole('user_1', $customer->id, 'member', ['x']);

    $checker = app(AccessChecker::class);

    expect($checker->can('user_1', 'x', $reseller->id))->toBeFalse()  // child role does not roll UP
        ->and($checker->can('user_1', 'x', $other->id))->toBeFalse();  // nor sideways
});

it('emits an event and records audit on assignment', function (): void {
    $org = $this->makeOrganization();
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $role = app(Roles::class)->define($org->id, 'admin');
    app(Roles::class)->assign($org->id, 'user_1', $role->id);

    $events->assertEmitted('role.assigned');
    $audit->assertRecorded('role.assigned');
});

it('defines an app-scoped tenant role distinct from an org-wide one', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);

    $orgWide = $roles->define($org->id, 'Manager');
    $appScoped = $roles->define($org->id, 'Manager', clientId: 'app_billing');

    // Same name, same org, different app scope → two distinct roles (unique key is
    // organization_id, client_id, name), not a collision.
    expect($orgWide->id)->not->toBe($appScoped->id)
        ->and($orgWide->client_id)->toBeNull()
        ->and($appScoped->client_id)->toBe('app_billing');
});

it('scopes a granted permission to the role\'s client, reusing an app-declared permission', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);

    // The app declared this permission via its manifest (client-scoped).
    $declared = Permission::query()->create(['client_id' => 'app_billing', 'name' => 'invoices:refund']);

    // A tenant grants that permission to an app-scoped custom role.
    $role = $roles->define($org->id, 'Refunder', clientId: 'app_billing');
    $roles->grantPermission($org->id, $role->id, 'invoices:refund');

    // It reused the app's declared permission — no stray client_id-null duplicate.
    expect(Permission::query()->where('name', 'invoices:refund')->count())->toBe(1)
        ->and(DB::table('role_permission')->where('role_id', $role->id)->where('permission_id', $declared->id)->exists())->toBeTrue();
});

it('grants an org-wide role its permission under the null client scope', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);

    $role = $roles->define($org->id, 'Auditor'); // org-wide, client_id null
    $roles->grantPermission($org->id, $role->id, 'audit:read');

    $permission = Permission::query()->where('name', 'audit:read')->sole();
    expect($permission->client_id)->toBeNull();
});

it('will not grant a permission onto another tenant\'s role', function (): void {
    $mine = $this->makeOrganization('Mine');
    $theirs = $this->makeOrganization('Theirs');
    $roles = app(Roles::class);

    $theirRole = $roles->define($theirs->id, 'Admin');

    expect(fn () => $roles->grantPermission($mine->id, $theirRole->id, 'x'))
        ->toThrow(UnknownRole::class);
    expect(DB::table('role_permission')->where('role_id', $theirRole->id)->count())->toBe(0);
});
