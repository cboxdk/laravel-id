<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\ExternalRbacNotBound;
use Cbox\Id\AccessControl\NullAccessChecker;
use Cbox\Id\AccessControl\UnboundGroupRoleMappings;
use Cbox\Id\AccessControl\UnboundRoles;
use Cbox\Id\AccessControl\ValueObjects\AppAccessClaims;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

/**
 * Under `access_control.driver = external` the host brings its own RBAC. The
 * built-in tables must not be created, authorization must deny-by-default, the
 * write/sync contracts must fail loud, and a host binding must win.
 *
 * `RefreshDatabase` IS DECLARED HERE, and that is the whole point of the first test.
 * `tests/Pest.php` applies the trait to this folder only on a SERVER engine — on sqlite
 * the migrator never runs, so `hasTable('roles')` was false whatever the driver said, and
 * "the built-in tables are not created" passed identically with the driver set to
 * `builtin`. Verified: breaking the env var that selects the driver turned the other two
 * tests red and left that one green. It had teeth on the MySQL and Postgres legs and none
 * at all on the default local run, which is the run somebody does before pushing.
 *
 * Declaring it in the file makes the assertion mean the same thing on every engine. It is
 * idempotent with the conditional binding — Pest applies the trait once.
 */
uses(RefreshDatabase::class);

it('does not create the built-in RBAC tables', function (): void {
    expect(Schema::hasTable('roles'))->toBeFalse()
        ->and(Schema::hasTable('permissions'))->toBeFalse()
        ->and(Schema::hasTable('role_permission'))->toBeFalse()
        ->and(Schema::hasTable('role_assignments'))->toBeFalse()
        ->and(Schema::hasTable('group_role_mappings'))->toBeFalse()
        ->and(Schema::hasTable('app_manifests'))->toBeFalse();
});

it('binds a deny-by-default AccessChecker', function (): void {
    $checker = app(AccessChecker::class);

    expect($checker)->toBeInstanceOf(NullAccessChecker::class)
        ->and($checker->can('user_1', 'billing.read', 'org_1'))->toBeFalse()
        ->and($checker->permissionsFor('user_1', 'org_1'))->toBe([])
        ->and($checker->forToken('user_1', 'org_1', 'client_1'))
        ->toEqual(new AppAccessClaims([], []));
});

it('fails loud on the write and sync contracts', function (): void {
    expect(app(Roles::class))->toBeInstanceOf(UnboundRoles::class)
        ->and(app(GroupRoleMappings::class))->toBeInstanceOf(UnboundGroupRoleMappings::class);

    expect(fn () => app(Roles::class)->define('org_1', 'admin'))
        ->toThrow(ExternalRbacNotBound::class);

    expect(fn () => app(GroupRoleMappings::class)->reconcileUser('org_1', 'user_1'))
        ->toThrow(ExternalRbacNotBound::class);
});

it('lets a host binding win over the deny-by-default fallback', function (): void {
    $fake = new class implements AccessChecker
    {
        public function can(string $userId, string $permission, string $organizationId): bool
        {
            return true;
        }

        public function permissionsFor(string $userId, string $organizationId): array
        {
            return ['billing.read'];
        }

        public function forToken(string $userId, ?string $organizationId, string $clientId): AppAccessClaims
        {
            return new AppAccessClaims(['admin'], ['billing.read']);
        }
    };

    app()->singleton(AccessChecker::class, fn () => $fake);

    $checker = app(AccessChecker::class);

    expect($checker)->toBe($fake)
        ->and($checker->can('user_1', 'billing.read', 'org_1'))->toBeTrue();
});
