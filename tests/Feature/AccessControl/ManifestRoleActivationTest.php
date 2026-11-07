<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\RoleDefinitionChanged;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\ManifestRoleDefinitions;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function publishReaderDefinition(array $permissions, bool $assignable = true): Role
{
    app(AppManifests::class)->sync('app_sites', app(ManifestParser::class)->parse([
        'version' => 'test',
        'permissions' => [['key' => 'sites:read'], ['key' => 'sites:publish']],
        'roles' => [['key' => 'reader', 'name' => 'Reader', 'permissions' => $permissions, 'tenant_assignable' => $assignable]],
    ]));

    return Role::query()->where('client_id', 'app_sites')->where('key', 'reader')->sole();
}

it('discovers permissions without widening existing role grants', function (): void {
    $org = $this->makeOrganization();
    $role = publishReaderDefinition(['sites:read']);
    app(Roles::class)->assign($org->id, 'person', $role->id);
    $changed = publishReaderDefinition(['sites:read', 'sites:publish']);

    expect(app(AccessChecker::class)->can('person', 'sites:read', $org->id))->toBeTrue()
        ->and(app(AccessChecker::class)->can('person', 'sites:publish', $org->id))->toBeFalse()
        ->and($changed->pending_permission_keys)->toBe(['sites:publish', 'sites:read'])
        ->and($changed->pending_definition_version)->not->toBeNull()
        ->and(RoleAssignment::query()->count())->toBe(1);

    app(ManifestRoleDefinitions::class)->activate($role->id, $changed->pending_definition_version, AuditActor::user('operator'));

    expect(app(AccessChecker::class)->can('person', 'sites:publish', $org->id))->toBeTrue()
        ->and($role->refresh()->pending_definition_version)->toBeNull()
        ->and(RoleAssignment::query()->count())->toBe(1);
});

it('requires a fresh review when the pending definition changes', function (): void {
    $role = publishReaderDefinition(['sites:read']);
    $first = publishReaderDefinition(['sites:read', 'sites:publish'])->pending_definition_version;
    publishReaderDefinition(['sites:publish']);

    expect(fn () => app(ManifestRoleDefinitions::class)->activate($role->id, $first, AuditActor::user('operator')))
        ->toThrow(RoleDefinitionChanged::class);
});

it('does not widen who may assign a staff role during publication', function (): void {
    $role = publishReaderDefinition(['sites:read'], false);
    $changed = publishReaderDefinition(['sites:read'], true);

    expect($changed->tenant_assignable)->toBeFalse()
        ->and($changed->pending_tenant_assignable)->toBeTrue();

    app(ManifestRoleDefinitions::class)->activate($role->id, $changed->pending_definition_version, AuditActor::user('operator'));
    expect($role->refresh()->tenant_assignable)->toBeTrue();
});

it('does not restore revoked permissions when an old manifest is redeployed', function (): void {
    $org = $this->makeOrganization();
    $role = publishReaderDefinition(['sites:read', 'sites:publish']);
    app(Roles::class)->assign($org->id, 'person', $role->id);
    $changed = publishReaderDefinition(['sites:read']);
    app(ManifestRoleDefinitions::class)->activate($role->id, $changed->pending_definition_version, AuditActor::user('operator'));
    publishReaderDefinition(['sites:read', 'sites:publish']);

    expect(app(AccessChecker::class)->can('person', 'sites:publish', $org->id))->toBeFalse();
});

it('does not assign a newly discovered role to anyone', function (): void {
    publishReaderDefinition(['sites:read']);

    expect(RoleAssignment::query()->count())->toBe(0);
});
