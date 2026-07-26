<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Listeners\ReconcileGroupRolesOnDomainEvent;
use Cbox\Id\AccessControl\Models\GroupRoleMapping;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Organization\Models\Organization;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * A directory with one group ("Engineering") containing a provisioned, linked user,
 * plus a role to map onto.
 *
 * @return array{0: Organization, 1: DirectoryGroup, 2: Role, 3: string}
 */
function engineeringGroup(): array
{
    $org = test()->makeOrganization();
    $directory = test()->makeDirectory($org->id)->directory;
    $member = app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('u1', 'alice', 'alice@corp.com'));
    $group = app(DirectoryGroups::class)->create($directory, 'Engineering', 'g1', [$member->id]);
    $role = app(Roles::class)->define($org->id, 'Developer');

    return [$org, $group, $role, (string) $member->user_id];
}

function hasAssignment(string $userId, string $roleId, ?GrantSource $source = null): bool
{
    return RoleAssignment::query()
        ->where('user_id', $userId)
        ->where('role_id', $roleId)
        ->when($source !== null, fn ($q) => $q->where('source', $source->value))
        ->exists();
}

it('grants a mapped role (pushed) to group members', function (): void {
    [$org, $group, $role, $userId] = engineeringGroup();

    app(GroupRoleMappings::class)->map($org->id, $group->id, $role->id);

    expect(hasAssignment($userId, $role->id, GrantSource::Pushed))->toBeTrue();
});

it('revokes the pushed role when the mapping is removed', function (): void {
    [$org, $group, $role, $userId] = engineeringGroup();
    $mappings = app(GroupRoleMappings::class);

    $mappings->map($org->id, $group->id, $role->id);
    $mappings->unmap($org->id, $group->id, $role->id);

    expect(hasAssignment($userId, $role->id))->toBeFalse();
});

it('reconciles group roles when a directory membership-changed event is delivered', function (): void {
    [$org, $group, $role, $userId] = engineeringGroup();
    // Create the mapping directly, bypassing map()'s own auto-reconcile, so the only
    // thing that can grant the role is the delivered event.
    GroupRoleMapping::query()->create([
        'organization_id' => $org->id, 'group_id' => $group->id, 'role_id' => $role->id, 'priority' => 0,
    ]);
    expect(hasAssignment($userId, $role->id))->toBeFalse();

    $event = new Event(['type' => 'directory.group.membership_changed', 'payload' => ['group_id' => $group->id, 'organization_id' => $org->id]]);
    app(ReconcileGroupRolesOnDomainEvent::class)->handle(new EventDelivered($event));

    expect(hasAssignment($userId, $role->id, GrantSource::Pushed))->toBeTrue();
});

it('never disturbs a manual assignment while reconciling group roles', function (): void {
    [$org, $group, $role, $userId] = engineeringGroup();
    $admin = app(Roles::class)->define($org->id, 'Admin');
    app(Roles::class)->assign($org->id, $userId, $admin->id, GrantSource::Manual);

    $mappings = app(GroupRoleMappings::class);
    $mappings->map($org->id, $group->id, $role->id);
    $mappings->unmap($org->id, $group->id, $role->id);

    // The hand-granted Admin survives the whole map/unmap cycle.
    expect(hasAssignment($userId, $admin->id, GrantSource::Manual))->toBeTrue()
        ->and(hasAssignment($userId, $role->id))->toBeFalse();
});

/**
 * Deleting a role must take its mappings with it.
 *
 * `group_role_mappings` has neither a foreign key nor a cascade, so a delete that leaves
 * them behind arms a poison pill: the next reconcile of that group plucks the dead role
 * id, calls assign(), and assertAssignableIn() throws. That reconcile runs on the RELAY
 * ({@see ReconcileGroupRolesOnDomainEvent}), whose failure isolation releases the claim —
 * so the outbox row is retried on every pass forever, is never prunable (the pruner needs
 * `dispatched_at`), counts as backlog permanently, and skips every listener registered
 * after AccessControl (webhooks, provisioning, metering, audit streaming) for that event
 * on every single pass.
 */
it('takes the group→role mappings with the role it deletes', function (): void {
    [$org, $group, $role, $userId] = engineeringGroup();

    app(GroupRoleMappings::class)->map($org->id, $group->id, $role->id);

    expect(hasAssignment($userId, $role->id, GrantSource::Pushed))->toBeTrue()
        ->and(GroupRoleMapping::query()->where('role_id', $role->id)->count())->toBe(1);

    app(Roles::class)->deleteRole($role->id);

    expect(GroupRoleMapping::query()->where('role_id', $role->id)->count())->toBe(0);

    // ...and the reconciler the mapping feeds still runs, on this pass and every one after.
    app(GroupRoleMappings::class)->reconcileGroup($group->id, $org->id);

    expect(hasAssignment($userId, $role->id))->toBeFalse();
});

/**
 * Belt and braces for the same failure: even a mapping that DOES survive — written before
 * the cascade existed, or by any other route — must not be able to wedge the relay.
 */
it('skips a mapped role that no longer resolves instead of throwing', function (): void {
    [$org, $group, $role, $userId] = engineeringGroup();

    app(GroupRoleMappings::class)->map($org->id, $group->id, $role->id);

    // Delete the role WITHOUT the service, exactly as the pre-fix delete left things.
    Role::query()->whereKey($role->id)->delete();
    RoleAssignment::query()->where('role_id', $role->id)->delete();

    expect(GroupRoleMapping::query()->where('role_id', $role->id)->count())->toBe(1);

    app(GroupRoleMappings::class)->reconcileUser($org->id, $userId);

    expect(hasAssignment($userId, $role->id))->toBeFalse();
});
