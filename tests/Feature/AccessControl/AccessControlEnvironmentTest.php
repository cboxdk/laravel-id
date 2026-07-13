<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * Roles — including system roles (org = null) — are environment-owned, so a role
 * defined in one environment can never be resolved, listed, or assigned from
 * another.
 */
it('scopes roles to their environment', function (): void {
    $role = $this->runAsEnvironment('env_a', fn () => Role::create([
        'organization_id' => 'org_1',
        'name' => 'admin',
    ]));

    // A system role (org = null) in env_a as well.
    $this->runAsEnvironment('env_a', fn () => Role::create(['organization_id' => null, 'name' => 'system']));

    // Auto-stamped on create.
    expect($role->environment_id)->toBe('env_a');

    // From env_b nothing is visible — not org roles, not system roles, not by key.
    $this->runAsEnvironment('env_b', function () use ($role): void {
        expect(Role::count())->toBe(0)
            ->and(Role::where('name', 'admin')->exists())->toBeFalse()
            ->and(Role::where('name', 'system')->exists())->toBeFalse()
            ->and(Role::find($role->id))->toBeNull();
    });

    // From env_a both roles are present.
    $this->runAsEnvironment('env_a', fn () => expect(Role::count())->toBe(2));
})->group('isolation');
