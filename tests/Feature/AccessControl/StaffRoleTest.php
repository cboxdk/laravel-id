<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\GroupRoleMappings;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Exceptions\InvalidManifest;
use Cbox\Id\AccessControl\Exceptions\RoleNotTenantAssignable;
use Cbox\Id\AccessControl\Exceptions\UnknownRole;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\AccessControl\Models\RoleAssignment;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * STAFF ROLES: an app vendor's own support people and administrators.
 *
 * They need rights across every customer of ONE app, and sometimes inside one customer
 * only. Two things stood in the way. An environment-wide grant accepted only app-agnostic
 * roles, so a cadastre "Support" role had to be one that appeared in EVERY app's token in
 * the environment, the tax app included. And nothing stopped a tenant administrator from
 * handing a staff role to one of their own members, because a role had no way to say it
 * was not the tenant's to give.
 */

/**
 * @param  list<array<string, mixed>>  $roles
 * @return array<string, mixed>
 */
function staffManifest(array $roles): array
{
    return [
        'version' => '1',
        'permissions' => [
            ['key' => 'parcels:read', 'description' => 'View parcels'],
            ['key' => 'support:impersonate', 'description' => 'Act as a customer'],
        ],
        'roles' => $roles,
    ];
}

function registerApp(string $name): Client
{
    return app(ClientRegistry::class)->register(new NewClient($name, ClientType::Confidential, redirectUris: ['https://'.strtolower($name).'.test/cb']))->client;
}

/** @return array<string, mixed> */
function accessTokenClaims(Client $client, string $userId, ?string $organizationId): array
{
    $issued = app(TokenIssuer::class)->issueForUser($client, $userId, $organizationId);

    return app(TokenSigner::class)->verify($issued->token, [SigningAlg::RS256])->all();
}

it('reads a staff role from the manifest and stores it as not tenant-assignable', function (): void {
    $manifest = app(ManifestParser::class)->parse(staffManifest([
        ['key' => 'support', 'name' => 'Support', 'permissions' => ['support:impersonate'], 'tenant_assignable' => false],
        ['key' => 'viewer', 'name' => 'Viewer', 'permissions' => ['parcels:read']],
    ]));

    app(AppManifests::class)->sync('app_cadastre', $manifest);

    expect(Role::query()->where('key', 'support')->value('tenant_assignable'))->toBeFalse()
        // Absent means assignable: the ordinary app role is the tenant's to hand out.
        ->and(Role::query()->where('key', 'viewer')->value('tenant_assignable'))->toBeTrue();
});

/**
 * @group security
 *
 * The permission flag reads anything but `true` as "no", which is safe because its
 * default is the narrow one. A role's default is the WIDE one, so the same leniency
 * would read a staff role declared as the string "false" as assignable by every tenant.
 */
it('refuses a role tenant_assignable that is not a boolean', function (mixed $value): void {
    expect(fn () => app(ManifestParser::class)->parse(staffManifest([
        ['key' => 'support', 'name' => 'Support', 'permissions' => [], 'tenant_assignable' => $value],
    ])))->toThrow(InvalidManifest::class, 'role "support" tenant_assignable must be true or false.');
})->with(['string false' => 'false', 'zero' => 0, 'null' => null])->group('security');

/**
 * An unchanged checksum skips the sync. If the staff marker were not in it, an app that
 * marked its Support role staff-only in a new deploy would leave it assignable by every
 * tenant for as long as nothing else in the manifest changed.
 */
it('re-syncs when a role becomes staff-only, and hashes an ordinary manifest as before', function (): void {
    $ordinary = app(ManifestParser::class)->parse(staffManifest([
        ['key' => 'support', 'name' => 'Support', 'permissions' => ['support:impersonate']],
    ]));
    $staff = app(ManifestParser::class)->parse(staffManifest([
        ['key' => 'support', 'name' => 'Support', 'permissions' => ['support:impersonate'], 'tenant_assignable' => false],
    ]));
    $explicitTrue = app(ManifestParser::class)->parse(staffManifest([
        ['key' => 'support', 'name' => 'Support', 'permissions' => ['support:impersonate'], 'tenant_assignable' => true],
    ]));

    // The default, spelled out or not, is the same bytes every SDK already produces.
    expect($explicitTrue->checksum())->toBe($ordinary->checksum())
        ->and($staff->checksum())->not->toBe($ordinary->checksum());

    app(AppManifests::class)->sync('app_cadastre', $ordinary);
    $result = app(AppManifests::class)->sync('app_cadastre', $staff);

    expect($result->unchanged)->toBeFalse()
        ->and(Role::query()->where('key', 'support')->value('tenant_assignable'))->toBeFalse();
});

it('lists only what a tenant may grant: its own and shared roles, never staff, orphaned or foreign ones', function (): void {
    $roles = app(Roles::class);

    $own = $roles->define('org-a', 'Editor');
    $shared = $roles->define(null, 'Viewer');
    $roles->define(null, 'Support', tenantAssignable: false);
    $roles->define('org-b', 'Their editor');
    $orphan = $roles->define(null, 'Retired', clientId: 'app_cadastre');
    $orphan->forceFill(['orphaned_at' => now()])->save();
    $cadastre = $roles->define(null, 'Surveyor', clientId: 'app_cadastre');
    $tax = $roles->define(null, 'Accountant', clientId: 'app_tax');

    $ids = static fn (array $list): array => array_map(static fn (Role $role): string => $role->id, $list);

    expect($ids($roles->tenantAssignableRoles('org-a')))
        ->toEqualCanonicalizing([$own->id, $shared->id, $cadastre->id, $tax->id]);

    // Narrowed to one app: its roles plus the app-agnostic ones, never another app's.
    expect($ids($roles->tenantAssignableRoles('org-a', 'app_cadastre')))
        ->toEqualCanonicalizing([$own->id, $shared->id, $cadastre->id]);
});

/**
 * @group security
 *
 * THE TENANT-PLANE GUARD. A customer's administrator who learns the id of the vendor's
 * staff role must not be able to grant it by naming it — a staff role usually carries
 * rights across every customer, so that is an escalation out of their tenancy.
 */
it('refuses a staff role on the tenant plane and writes nothing', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support', tenantAssignable: false);

    expect(fn () => $roles->assignAsTenant('org-a', 'user-1', $support->id))
        ->toThrow(RoleNotTenantAssignable::class, "Role [{$support->id}] cannot be granted from the organization plane.");

    expect(RoleAssignment::query()->where('user_id', 'user-1')->exists())->toBeFalse();
})->group('security');

it('lets the tenant plane grant an ordinary role', function (): void {
    $roles = app(Roles::class);
    $viewer = $roles->define(null, 'Viewer');

    $roles->assignAsTenant('org-a', 'user-1', $viewer->id);

    expect($roles->assignmentsForSubject('org-a', 'user-1'))->toBe([$viewer->id]);
});

/**
 * @group security
 *
 * The same guard also refuses what the organization fence refuses, so a tenant-plane
 * caller does not need to remember to ask both questions.
 */
it('refuses another organization’s role on the tenant plane', function (): void {
    $roles = app(Roles::class);
    $theirs = $roles->define('org-b', 'Editor');

    expect(fn () => $roles->assertTenantAssignable('org-a', $theirs->id))
        ->toThrow(RoleNotTenantAssignable::class);
})->group('security');

/**
 * Tenant-specific staff rights: the ENVIRONMENT plane may still give a staff role inside
 * one customer only. assign() is that plane's call.
 */
it('lets an environment administrator grant a staff role inside one organization', function (): void {
    $roles = app(Roles::class);
    $client = registerApp('Cadastre');
    $support = $roles->define(null, 'Support', clientId: $client->client_id, tenantAssignable: false);

    $roles->assign('org-a', 'user-1', $support->id);

    expect(app(AccessChecker::class)->forToken('user-1', 'org-a', $client->client_id)->roles)->toBe(['Support'])
        ->and(app(AccessChecker::class)->forToken('user-1', 'org-b', $client->client_id)->roles)->toBe([]);
});

/**
 * @group security
 *
 * Whoever writes a directory mapping, the CUSTOMER's IdP decides who is in the group. A
 * staff role mapped there is a customer handing out the vendor's staff role with one
 * more hop.
 */
it('refuses to map a directory group to a staff role', function (): void {
    $support = app(Roles::class)->define(null, 'Support', tenantAssignable: false);

    expect(fn () => app(GroupRoleMappings::class)->map('org-a', 'group-1', $support->id))
        ->toThrow(RoleNotTenantAssignable::class);
})->group('security');

it('never lets a tenant un-mark the environment’s staff role', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support', tenantAssignable: false);

    // A tenant resolves only its own roles, so it cannot un-mark the vendor's.
    expect(fn () => $roles->updateRole($support->id, 'Support', null, 'org-a', tenantAssignable: true))
        ->toThrow(UnknownRole::class);

    expect($support->fresh()?->tenant_assignable)->toBeFalse();
})->group('security');

it('records the staff flag changing on the role’s audit entry', function (): void {
    $audit = $this->fakeAudit();
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support');

    $roles->updateRole($support->id, 'Support', null, null, tenantAssignable: false);

    $audit->assertRecorded('role.updated', fn ($event): bool => $event->context['from']['tenant_assignable'] === true
        && $event->context['to']['tenant_assignable'] === false);
});

/*
 * --------------------------------------------------------------------------
 * Environment-wide grants of ONE app's role
 * --------------------------------------------------------------------------
 */

/**
 * @group security
 *
 * THE LEAK THIS WHOLE CHANGE EXISTS TO PREVENT. Two apps in one environment. Cadastre's
 * support staff hold cadastre's Support role everywhere. That grant must reach every
 * cadastre token — in any organization, and with none — and never a tax-app token.
 */
it('keeps an environment-wide grant of one app’s role out of every other app’s token', function (): void {
    $cadastre = registerApp('Cadastre');
    $tax = registerApp('Tax');
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support', clientId: $cadastre->client_id, tenantAssignable: false);
    $roles->grantPermission(null, $support->id, 'support:impersonate');

    $roles->assignEverywhere('staff-1', $support->id);

    foreach (['org-a', 'org-b', null] as $organizationId) {
        $inCadastre = accessTokenClaims($cadastre, 'staff-1', $organizationId);
        $inTax = accessTokenClaims($tax, 'staff-1', $organizationId);

        expect($inCadastre['roles'] ?? null)->toBe(['Support'])
            ->and($inCadastre['permissions'] ?? null)->toBe(['support:impersonate'])
            ->and($inTax)->not->toHaveKey('roles')
            ->and($inTax)->not->toHaveKey('permissions');
    }
})->group('security');

it('still grants an app-agnostic role everywhere into every app', function (): void {
    $cadastre = registerApp('Cadastre');
    $tax = registerApp('Tax');
    $roles = app(Roles::class);

    $auditor = $roles->define(null, 'Auditor');
    $roles->assignEverywhere('staff-1', $auditor->id);

    expect(accessTokenClaims($cadastre, 'staff-1', 'org-a')['roles'] ?? null)->toBe(['Auditor'])
        ->and(accessTokenClaims($tax, 'staff-1', 'org-a')['roles'] ?? null)->toBe(['Auditor']);
});

/**
 * @group security
 *
 * An app role nobody believes in any more stays ungrantable everywhere, as it is inside
 * one organization.
 */
it('refuses to grant an orphaned app role everywhere', function (): void {
    $roles = app(Roles::class);
    $retired = $roles->define(null, 'Retired', clientId: 'app_cadastre');
    $retired->forceFill(['orphaned_at' => now()])->save();

    expect(fn () => $roles->assignEverywhere('staff-1', $retired->id))
        ->toThrow(UnknownRole::class, "Role [{$retired->id}] does not exist in this organization.");
})->group('security');

it('names the app an environment-wide grant reaches on its event and audit entry', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $roles = app(Roles::class);

    $support = $roles->define(null, 'Support', clientId: 'app_cadastre', tenantAssignable: false);
    $roles->assignEverywhere('staff-1', $support->id);
    $roles->unassignEverywhere('staff-1', $support->id);

    $events->assertEmitted('role.assigned_everywhere', fn ($event): bool => $event->payload['client_id'] === 'app_cadastre'
        && $event->payload['role_id'] === $support->id
        && $event->organizationId === null);
    $events->assertEmitted('role.unassigned_everywhere', fn ($event): bool => $event->payload['client_id'] === 'app_cadastre');
    $audit->assertRecorded('role.assigned_everywhere', fn ($event): bool => $event->context['client_id'] === 'app_cadastre');
});
