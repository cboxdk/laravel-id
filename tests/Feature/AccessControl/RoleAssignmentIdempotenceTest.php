<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Events\Models\Event;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * assign()/unassign() announce a STATE CHANGE, not a call.
 *
 * The directory reconciler compares the mapped roles against the assignments
 * whose source is `pushed`, so a user holding a mapped role via a MANUAL grant is
 * never in that set and gets re-assigned on EVERY reconcile. When the emit was
 * unconditional that wrote one outbox row plus one hash-chained audit entry per
 * such user per pass — pure noise that consumed a relay slot each time.
 */
it('emits nothing and audits nothing when the role is already held', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'admin');

    $roles->assign($org->id, 'user_1', $role->id);

    // Scoped to the org under test, not counted globally: `events` and `audit_logs` are
    // platform-wide tables, so a bare count is every other test's rows too under --parallel.
    $eventsAfterFirst = Event::query()->where('organization_id', $org->id)->where('type', 'role.assigned')->count();
    $auditAfterFirst = AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.assigned')->count();

    expect($eventsAfterFirst)->toBe(1)->and($auditAfterFirst)->toBe(1);

    // Re-assigning is a no-op on the row — including from a DIFFERENT source, which
    // is exactly the reconciler's shape (manual grant, pushed reconcile).
    $again = $roles->assign($org->id, 'user_1', $role->id, GrantSource::Pushed);

    expect($again->wasRecentlyCreated)->toBeFalse()
        ->and(RoleAssignment::query()->where('organization_id', $org->id)->count())->toBe(1)
        ->and(Event::query()->where('organization_id', $org->id)->where('type', 'role.assigned')->count())->toBe(1)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.assigned')->count())->toBe(1);
});

it('still emits and audits when the assignment is actually created', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'admin');

    $roles->assign($org->id, 'user_1', $role->id);
    $roles->assign($org->id, 'user_2', $role->id);

    expect(Event::query()->where('organization_id', $org->id)->where('type', 'role.assigned')->count())->toBe(2)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.assigned')->count())->toBe(2);
});

it('emits nothing when revoking a role the user does not hold', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'admin');

    $roles->unassign($org->id, 'user_1', $role->id);

    expect(Event::query()->where('organization_id', $org->id)->where('type', 'role.unassigned')->count())->toBe(0)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.unassigned')->count())->toBe(0);

    // ...but a real revocation still announces itself.
    $roles->assign($org->id, 'user_1', $role->id);
    $roles->unassign($org->id, 'user_1', $role->id);

    expect(Event::query()->where('organization_id', $org->id)->where('type', 'role.unassigned')->count())->toBe(1)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.unassigned')->count())->toBe(1);
});

it('keeps a repeated directory reconcile off the event relay entirely', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'admin');

    // The manual grant an admin made by hand.
    $roles->assign($org->id, 'user_1', $role->id);
    $baseline = Event::query()->where('organization_id', $org->id)->count();

    // Ten reconcile passes over the same unchanged state.
    for ($pass = 0; $pass < 10; $pass++) {
        $roles->assign($org->id, 'user_1', $role->id, GrantSource::Pushed);
    }

    expect(Event::query()->where('organization_id', $org->id)->count())->toBe($baseline);
});
