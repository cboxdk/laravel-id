<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\AppManifests;
use Cbox\Id\AccessControl\Contracts\PermissionDecisions;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\AccessControl\Manifest\ManifestParser;
use Cbox\Id\AccessControl\Models\Permission;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Models\User;
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
 * A NAME AN APP DECLARES BELONGS TO THAT APP.
 *
 * The `roles` and `permissions` claims are bare strings, and an organization's own roles
 * and permissions share their namespace with the ones an app declares. A token for an app
 * carries a name that app declares only when the person holds it through the app's own
 * declared row. A row an organization wrote under the same name is not that row, and
 * `tenant_assignable: false` (how an app keeps a key off the tenant plane) depends on it.
 */

beforeEach(function (): void {
    User::query()->create(['id' => 'member-1', 'email' => 'member-1@tokens.test', 'status' => UserStatus::Active]);
});

function declaredNamesApp(string $name = 'Ledger'): Client
{
    $client = app(ClientRegistry::class)->register(new NewClient($name, ClientType::Confidential, redirectUris: ['https://'.strtolower($name).'.test/cb']))->client;

    app(AppManifests::class)->sync($client->client_id, app(ManifestParser::class)->parse([
        'version' => '1',
        'permissions' => [
            ['key' => 'ledger:read', 'description' => 'Read the ledger', 'tenant_assignable' => true],
            ['key' => 'ledger:override', 'description' => 'Staff override', 'tenant_assignable' => false],
        ],
        'roles' => [
            ['key' => 'reader', 'name' => 'Reader', 'permissions' => ['ledger:read']],
            ['key' => 'support', 'name' => 'Support', 'permissions' => ['ledger:override'], 'tenant_assignable' => false],
        ],
    ]));

    return $client;
}

function declaredRole(Client $client, string $key): Role
{
    return Role::query()->where('client_id', $client->client_id)->where('key', $key)->firstOrFail();
}

it('keeps a manual permission named like an app-declared key out of that app\'s token', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp();

    $orgRole = $roles->define('org-a', 'Bookkeeper');
    $roles->grantPermission('org-a', $orgRole->id, 'ledger:override');
    $roles->grantPermission('org-a', $orgRole->id, 'reports:export');
    $roles->assign('org-a', 'member-1', $orgRole->id);

    // The manual row exists and the role holds it; it is just not the app's key.
    expect(Permission::query()->whereNull('client_id')->where('name', 'ledger:override')->exists())->toBeTrue();

    $claims = app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id);

    expect($claims->permissions)->toBe(['reports:export'])
        ->and($claims->roles)->toBe(['Bookkeeper']);
})->group('security');

it('drops a manual permission that differs from the declared key only in case', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp();

    $orgRole = $roles->define('org-a', 'Bookkeeper');
    $roles->grantPermission('org-a', $orgRole->id, 'Ledger:Override');
    $roles->assign('org-a', 'member-1', $orgRole->id);

    expect(app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id)->permissions)->toBe([]);
})->group('security');

it('drops another app\'s declared row spelled like this app\'s key', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp('Ledger');
    $other = declaredNamesApp('Other');

    $orgRole = $roles->define('org-a', 'Bookkeeper');
    $otherRow = Permission::query()->where('client_id', $other->client_id)->where('name', 'ledger:override')->firstOrFail();
    $roles->attachPermission($orgRole->id, $otherRow->id, 'org-a');
    $roles->assign('org-a', 'member-1', $orgRole->id);

    expect(app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id)->permissions)->toBe([]);
})->group('security');

it('carries a declared key held through the app\'s own role, once, beside a same-named manual row', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp();

    $roles->assign('org-a', 'member-1', declaredRole($ledger, 'support')->id);
    $roles->assign('org-a', 'member-1', declaredRole($ledger, 'reader')->id);

    $orgRole = $roles->define('org-a', 'Bookkeeper');
    $roles->grantPermission('org-a', $orgRole->id, 'ledger:override');
    $roles->assign('org-a', 'member-1', $orgRole->id);

    $claims = app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id);

    expect($claims->permissions)->toBe(['ledger:override', 'ledger:read'])
        ->and($claims->roles)->toBe(['Bookkeeper', 'reader', 'support']);
});

it('leaves a manual permission no app declares in the token', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp();

    $shared = $roles->define(null, 'Auditor');
    $roles->grantPermission(null, $shared->id, 'audit:read');
    $roles->assign('org-a', 'member-1', $shared->id);

    $claims = app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id);

    expect($claims->permissions)->toBe(['audit:read'])
        ->and($claims->roles)->toBe(['Auditor']);
});

it('keeps an organization role named like an app role key out of that app\'s roles claim', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp();

    $orgRole = $roles->define('org-a', 'support');
    $roles->grantPermission('org-a', $orgRole->id, 'reports:export');
    $roles->assign('org-a', 'member-1', $orgRole->id);

    $claims = app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id);

    // The role's own, undeclared permissions still apply; only the borrowed name goes.
    expect($claims->roles)->toBe([])
        ->and($claims->permissions)->toBe(['reports:export']);

    // The app's own role of that key still reads as itself.
    $roles->assign('org-a', 'member-1', declaredRole($ledger, 'support')->id);

    expect(app(AccessChecker::class)->forToken('member-1', 'org-a', $ledger->client_id)->roles)->toBe(['support']);
})->group('security');

it('applies the same rule to the signed token and to permission decisions', function (): void {
    $roles = app(Roles::class);
    $ledger = declaredNamesApp();

    $orgRole = $roles->define('org-a', 'support');
    $roles->grantPermission('org-a', $orgRole->id, 'ledger:override');
    $roles->assign('org-a', 'member-1', $orgRole->id);

    $issued = app(TokenIssuer::class)->issueForUser($ledger, 'member-1', 'org-a');
    $claims = app(TokenSigner::class)->verify($issued->token, [SigningAlg::RS256])->all();

    expect($claims)->not->toHaveKey('roles')
        ->and($claims)->not->toHaveKey('permissions');

    $decision = app(PermissionDecisions::class)->decide('member-1', 'org-a', $ledger->client_id, ['ledger:override']);

    expect($decision->checks[0]->allowed)->toBeFalse();
})->group('security');
