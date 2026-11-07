<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Enums\GrantSource;
use Cbox\Id\AccessControl\Erasure\RoleGrantsErasureStep;
use Cbox\Id\AccessControl\Models\GroupRoleMapping;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Directory\Contracts\DirectoryGroups;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Governance\Contracts\SegregationOfDuties;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\SubjectPseudonym;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('keeps an explicit manual grant after the directory mapping which first granted it is removed', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $member = app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('manual-promoted', 'alice', 'alice@corp.test'));
    $group = app(DirectoryGroups::class)->create($directory, 'Engineering', 'manual-promoted', [$member->id]);
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'Editor');
    $mappings = app(GroupRoleMappings::class);
    $mappings->map($org->id, $group->id, $role->id);
    expect(RoleAssignment::query()->where('role_id', $role->id)->firstOrFail()->source)->toBe(GrantSource::Pushed);

    $grant = $roles->assignAsTenant($org->id, $member->user_id, $role->id, GrantSource::Manual);
    expect($grant->source)->toBe(GrantSource::Manual)
        ->and(Event::query()->where('organization_id', $org->id)->where('type', 'role.assigned')->where('payload->from_source', 'pushed')->where('payload->source', 'manual')->count())->toBe(1)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.assigned')->where('context->from_source', 'pushed')->where('context->source', 'manual')->count())->toBe(1);
    $events = Event::query()->where('organization_id', $org->id)->count();
    $audits = AuditEntry::query()->where('organization_id', $org->id)->count();
    // Repeating manual intent is idempotent, including its audit/outbox effects.
    $roles->assignAsTenant($org->id, $member->user_id, $role->id, GrantSource::Manual);
    expect(Event::query()->where('organization_id', $org->id)->count())->toBe($events)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->count())->toBe($audits);

    $mappings->unmap($org->id, $group->id, $role->id);
    $mappings->reconcileUser($org->id, $member->user_id);
    expect(RoleAssignment::query()->where('role_id', $role->id)->firstOrFail()->source)->toBe(GrantSource::Manual)
        ->and(Event::query()->where('organization_id', $org->id)->where('type', 'role.unassigned')->count())->toBe(0);
});

it('never downgrades an existing manual grant when a directory push arrives', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'Editor');
    $manual = $roles->assign($org->id, 'manual_user', $role->id, GrantSource::Manual);
    $events = Event::query()->where('organization_id', $org->id)->count();
    $audits = AuditEntry::query()->where('organization_id', $org->id)->count();
    $pushed = $roles->assign($org->id, 'manual_user', $role->id, GrantSource::Pushed);
    expect($pushed->id)->toBe($manual->id)->and($pushed->source)->toBe(GrantSource::Manual)
        ->and(Event::query()->where('organization_id', $org->id)->count())->toBe($events)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->count())->toBe($audits);
});

it('withdraws a departed pushed holder when the final mapping is removed', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $member = app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('departed', 'bob', 'bob@corp.test'));
    $group = app(DirectoryGroups::class)->create($directory, 'Engineering', 'departed', [$member->id]);
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'Editor');
    $mappings = app(GroupRoleMappings::class);
    $mappings->map($org->id, $group->id, $role->id);
    // Model a previously persisted departure whose relay has not reconciled yet.
    DB::table('directory_group_members')->where('group_id', $group->id)->delete();
    $mappings->unmap($org->id, $group->id, $role->id);
    expect(RoleAssignment::query()->where('role_id', $role->id)->exists())->toBeFalse()
        ->and(Event::query()->where('organization_id', $org->id)->where('type', 'role.unassigned')->count())->toBe(1);
});

it('refuses a role becoming staff-only after the reconcile snapshot and still withdraws unrelated stale grants', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $member = app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('staff-race', 'carol', 'carol@corp.test'));
    $group = app(DirectoryGroups::class)->create($directory, 'Engineering', 'staff-race', [$member->id]);
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'Editor');
    $stale = $roles->define($org->id, 'Former');
    $roles->assign($org->id, $member->user_id, $stale->id, GrantSource::Pushed);
    GroupRoleMapping::query()->create(['organization_id' => $org->id, 'group_id' => $group->id, 'role_id' => $role->id]);
    $changed = false;
    // Inject exactly after the pre-filter read, before the grant's fresh check.
    DB::listen(function (QueryExecuted $query) use (&$changed, $role): void {
        if (! $changed && str_starts_with($query->sql, 'select') && str_contains($query->sql, 'tenant_assignable') && str_contains($query->sql, 'roles')) {
            $changed = true;
            Role::query()->whereKey($role->id)->update(['tenant_assignable' => false]);
        }
    });
    app(GroupRoleMappings::class)->reconcileUser($org->id, $member->user_id);
    expect($changed)->toBeTrue()
        ->and(RoleAssignment::query()->where('user_id', $member->user_id)->count())->toBe(0);
});

it('erases the subjects grant mutex only in the current environment', function (): void {
    $env = app(EnvironmentContext::class)->requireEnvironment()->environmentKey();
    DB::table('role_grant_subject_locks')->insert([
        ['environment_id' => $env, 'subject_id' => 'erased_user'],
        ['environment_id' => 'other_env', 'subject_id' => 'erased_user'],
        ['environment_id' => $env, 'subject_id' => 'retained_user'],
    ]);
    $result = app(RoleGrantsErasureStep::class)->erase(new ErasureRequest(
        'erased_user', null, null, SubjectPseudonym::fromToken('test'), AuditActor::system(),
    ));
    expect($result->count('role_grant_subject_locks'))->toBe(1)
        ->and(DB::table('role_grant_subject_locks')->count())->toBe(2)
        ->and(DB::table('role_grant_subject_locks')->where('environment_id', $env)->where('subject_id', 'erased_user')->exists())->toBeFalse();
});

it('replaces a conflicting pushed grant in one sync while preserving a conflicting manual grant', function (GrantSource $source): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $member = app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('replacement', 'dana', 'dana@corp.test'));
    $group = app(DirectoryGroups::class)->create($directory, 'Engineering', 'replacement', [$member->id]);
    $roles = app(Roles::class);
    $old = $roles->define($org->id, 'Prepare');
    $desired = $roles->define($org->id, 'Approve');
    app(SegregationOfDuties::class)->definePolicy($org->id, 'Separate preparation and approval', [$old->id, $desired->id]);
    $roles->assign($org->id, $member->user_id, $old->id, $source);
    GroupRoleMapping::query()->create(['organization_id' => $org->id, 'group_id' => $group->id, 'role_id' => $desired->id]);

    app(GroupRoleMappings::class)->reconcileUser($org->id, $member->user_id);

    $expected = $source === GrantSource::Pushed ? $desired->id : $old->id;
    expect(RoleAssignment::query()->where('user_id', $member->user_id)->pluck('role_id')->all())->toBe([$expected]);
    $withheld = AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.grant_withheld')->count();
    expect($withheld)->toBe($source === GrantSource::Pushed ? 0 : 1);
})->with([GrantSource::Pushed, GrantSource::Manual]);

it('does not count or announce a grant already removed with its role during bulk revocation', function (): void {
    $org = $this->makeOrganization();
    $roles = app(Roles::class);
    $role = $roles->define($org->id, 'Removed during bulk revoke');
    $roles->assign($org->id, 'bulk-revoke-user', $role->id);
    $deleted = false;
    DB::listen(function (QueryExecuted $query) use (&$deleted, $role, $roles, $org): void {
        if (! $deleted && str_starts_with($query->sql, 'select')
            && str_contains($query->sql, 'roles') && str_contains($query->sql, 'order by')) {
            $deleted = true;
            // Equivalent to a catalog deletion committing while bulk revocation
            // waits for the sorted role lock after its initial assignment snapshot.
            $roles->deleteRole($role->id, $org->id);
        }
    });
    $removed = $roles->unassignAll($org->id, 'bulk-revoke-user');
    expect($deleted)->toBeTrue()
        ->and($removed)->toBe(0)
        ->and(Event::query()->where('organization_id', $org->id)->where('type', 'role.unassigned')->count())->toBe(1)
        ->and(AuditEntry::query()->where('organization_id', $org->id)->where('action', 'role.unassigned')->count())->toBe(1);
});
