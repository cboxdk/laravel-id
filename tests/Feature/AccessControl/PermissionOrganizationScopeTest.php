<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Models\Permission;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @group isolation
 *
 * The organization tier of the permission catalog.
 *
 * `environment_id` is the hard boundary and has its own file. This one covers the soft
 * boundary INSIDE one environment: a manual permission authored by a tenant belongs to
 * that tenant, and a manual permission authored by the environment is shared with all of
 * them. Both predicates are named on the model rather than written at each call site,
 * because the console needs them to differ — a tenant reads the shared tier (their roles
 * are composed from it) and must not write to it.
 */

/** Author a manual permission directly, bypassing the console. */
function permissionOwnedBy(?string $organizationId, string $name): Permission
{
    return Permission::query()->create([
        'client_id' => null,
        'environment_id' => 'env_a',
        'organization_id' => $organizationId,
        'name' => $name,
        'tenant_assignable' => true,
    ]);
}

it('shows an organization its own rows and the shared tier, never a peer\'s', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        permissionOwnedBy('org_one', 'one:only');
        permissionOwnedBy('org_two', 'two:only');
        permissionOwnedBy(null, 'shared:all');

        $names = Permission::query()->visibleToOrganization('org_one')->pluck('name')->all();

        expect($names)->toHaveCount(2)
            ->and(in_array('one:only', $names, true))->toBeTrue()
            ->and(in_array('shared:all', $names, true))->toBeTrue()
            ->and(in_array('two:only', $names, true))->toBeFalse();
    });
})->group('isolation');

it('shows a null organization the shared tier alone', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        permissionOwnedBy('org_one', 'one:only');
        permissionOwnedBy(null, 'shared:all');

        // The environment plane, and operator tooling. Deliberately narrower than "all of
        // this environment": a tenant's keys are named after what that tenant bought, and
        // no console page needs to read them.
        $names = Permission::query()->visibleToOrganization(null)->pluck('name')->all();

        expect($names)->toBe(['shared:all']);
    });
})->group('isolation');

it('owns strictly less than it shows — the shared tier is readable, not writable', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        permissionOwnedBy('org_one', 'one:only');
        permissionOwnedBy(null, 'shared:all');

        $visible = Permission::query()->visibleToOrganization('org_one')->pluck('name')->all();
        $owned = Permission::query()->ownedByOrganization('org_one')->pluck('name')->all();

        // The difference between the two predicates IS the control: a fence built from
        // the visibility one would hand a tenant the environment's shared rows to delete,
        // and deleting one cascades `role_permission` for every role in the environment.
        expect($owned)->toBe(['one:only'])
            ->and(in_array('shared:all', $visible, true))->toBeTrue()
            ->and(in_array('shared:all', $owned, true))->toBeFalse();
    });
})->group('isolation');

it('does not let a peer organization own a row through the null tier', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        permissionOwnedBy('org_one', 'one:only');

        // `ownedByOrganization(null)` is the environment plane asking for the shared tier.
        // It must not match a row a tenant owns, or the environment-plane form would
        // resolve, edit and delete tenants' private keys as if they were its own.
        expect(Permission::query()->ownedByOrganization(null)->pluck('name')->all())->toBe([]);
    });
})->group('isolation');
