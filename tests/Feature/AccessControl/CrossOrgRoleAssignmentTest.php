<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * Two organizations inside ONE environment. The environment scope cannot separate them —
 * that boundary is the org, and it is enforced by role ownership. An admin of org A must
 * never be able to pull org B's role (and its permissions) into an org-A-scoped token.
 */

/** Give org B a privileged org-wide role carrying a permission org A must never get. */
function orgBPrivilegedRole(): Role
{
    $role = Role::create(['organization_id' => 'org_b', 'name' => 'finance-approver']);

    app(Roles::class)->grantPermission('org_b', $role->id, 'invoices:approve');

    return $role;
}

it('refuses to assign another organization\'s role', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        $foreign = orgBPrivilegedRole();

        // The console passes a client-supplied role id straight through — so the service
        // is the chokepoint that has to say no.
        expect(fn () => app(Roles::class)->assign('org_a', 'user_alice', $foreign->id))
            ->toThrow(UnknownRole::class);

        // …and nothing was written.
        expect(RoleAssignment::query()->where('role_id', $foreign->id)->exists())->toBeFalse();
    });
});

it('never surfaces a foreign role even when the assignment row already exists', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        $foreign = orgBPrivilegedRole();

        // Bypass the service entirely: write the row the old code would have written,
        // so this proves the READ path is independently safe rather than relying on
        // the write guard alone.
        DB::table('role_assignments')->insert([
            'id' => 'ra_forged',
            'environment_id' => 'env_a',
            'organization_id' => 'org_a',
            'user_id' => 'user_alice',
            'role_id' => $foreign->id,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $checker = app(AccessChecker::class);

        expect($checker->can('user_alice', 'invoices:approve', 'org_a'))->toBeFalse()
            ->and($checker->permissionsFor('user_alice', 'org_a'))->not->toContain('invoices:approve');

        // The token claims are the payload that actually reaches a relying app.
        $claims = $checker->forToken('user_alice', 'org_a', 'client_app');

        expect($claims->roles)->not->toContain('finance-approver')
            ->and($claims->permissions)->not->toContain('invoices:approve');
    });
});

it('still assigns the org\'s own roles and environment-wide system roles', function (): void {
    $this->runAsEnvironment('env_a', function (): void {
        $own = Role::create(['organization_id' => 'org_a', 'name' => 'billing-admin']);
        $system = Role::create(['organization_id' => null, 'name' => 'support']);

        app(Roles::class)->grantPermission('org_a', $own->id, 'invoices:read');

        app(Roles::class)->assign('org_a', 'user_alice', $own->id);
        app(Roles::class)->assign('org_a', 'user_alice', $system->id);

        expect(app(AccessChecker::class)->can('user_alice', 'invoices:read', 'org_a'))->toBeTrue();

        $claims = app(AccessChecker::class)->forToken('user_alice', 'org_a', 'client_app');

        // A system role (organization_id null) is shared across the environment by design.
        expect($claims->roles)->toContain('billing-admin')->toContain('support');
    });
});
