<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Events\Models\Event;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * The role CATALOG is privileged access: deleting a role, or changing which
 * permissions it carries, changes what every holder can do. Those writes used to be
 * raw `DB::table()` statements in the console — no observer, no FK cascade, nothing
 * on the audit trail and nothing on the outbox, so no SIEM saw the change and no
 * downstream app mirroring grants off `role.unassigned` ever learned.
 */
it('deletes a role, unassigns every holder, and records both', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'approver');

    $roles->assign($org->id, 'user_1', $role->id);
    $roles->assign($org->id, 'user_2', $role->id);
    $roles->grantPermission($org->id, $role->id, 'invoices.approve');

    $roles->deleteRole($role->id);

    expect(Role::query()->whereKey($role->id)->exists())->toBeFalse()
        ->and(RoleAssignment::query()->where('role_id', $role->id)->count())->toBe(0)
        ->and(DB::table('role_permission')->where('role_id', $role->id)->count())->toBe(0);

    // One role.unassigned per holder — the event a downstream mirror reconciles off.
    expect(Event::query()->where('type', 'role.unassigned')->count())->toBe(2)
        ->and(AuditEntry::query()->where('action', 'role.unassigned')->count())->toBe(2);

    $deleted = Event::query()->where('type', 'role.deleted')->sole();

    expect($deleted->payload['role_id'])->toBe($role->id)
        ->and($deleted->payload['user_ids'])->toEqualCanonicalizing(['user_1', 'user_2'])
        ->and(AuditEntry::query()->where('action', 'role.deleted')->count())->toBe(1);
});

it('records a permission being attached and revoked on a role', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'approver');
    $permission = Permission::query()->create(['name' => 'invoices.approve']);

    $roles->attachPermission($role->id, $permission->id);

    expect(DB::table('role_permission')->where('role_id', $role->id)->count())->toBe(1)
        ->and(Event::query()->where('type', 'role.permission_granted')->count())->toBe(1)
        ->and(AuditEntry::query()->where('action', 'role.permission_granted')->count())->toBe(1);

    // A STATE CHANGE, not a call: re-attaching what is already attached says nothing,
    // the same rule assign() follows.
    $roles->attachPermission($role->id, $permission->id);

    expect(Event::query()->where('type', 'role.permission_granted')->count())->toBe(1);

    $roles->revokePermission($role->id, $permission->id);

    expect(DB::table('role_permission')->where('role_id', $role->id)->count())->toBe(0)
        ->and(Event::query()->where('type', 'role.permission_revoked')->count())->toBe(1)
        ->and(AuditEntry::query()->where('action', 'role.permission_revoked')->count())->toBe(1);

    // Revoking one the role never held changed nothing, so it announces nothing.
    $roles->revokePermission($role->id, $permission->id);

    expect(Event::query()->where('type', 'role.permission_revoked')->count())->toBe(1);
});

it('records a rename with the values on both sides of it', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'approver', 'Approves invoices');

    $roles->updateRole($role->id, 'Payment approver', 'Approves outgoing payments');

    $entry = AuditEntry::query()->where('action', 'role.updated')->sole();

    expect($entry->context['from']['name'])->toBe('approver')
        ->and($entry->context['to']['name'])->toBe('Payment approver')
        ->and(Role::query()->whereKey($role->id)->value('name'))->toBe('Payment approver');
});

it('refuses every lifecycle operation against a role that does not exist', function (string $method, array $args): void {
    /** @var callable $call */
    $call = [app(Roles::class), $method];

    $call(...$args);
})->with([
    'delete' => ['deleteRole', ['01JZZZZZZZZZZZZZZZZZZZZZZZ']],
    'rename' => ['updateRole', ['01JZZZZZZZZZZZZZZZZZZZZZZZ', 'x']],
    'attach' => ['attachPermission', ['01JZZZZZZZZZZZZZZZZZZZZZZZ', 'p']],
    'revoke' => ['revokePermission', ['01JZZZZZZZZZZZZZZZZZZZZZZZ', 'p']],
])->throws(UnknownRole::class);
