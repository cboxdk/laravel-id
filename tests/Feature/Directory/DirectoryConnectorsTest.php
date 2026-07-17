<?php

declare(strict_types=1);

use Cbox\Id\Directory\Connectors\GoogleWorkspaceConnector;
use Cbox\Id\Directory\Connectors\MicrosoftEntraConnector;
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\Testing\FakeDirectoryConnector;
use Cbox\Id\Directory\ValueObjects\DirectoryGroupSnapshot;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

function testRsaKey(): string
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $pem);

    return $pem;
}

it('pulls and maps Google Workspace users (suspended → inactive)', function (): void {
    Http::fake([
        'oauth2.googleapis.com/token' => Http::response(['access_token' => 'ya29.token']),
        'admin.googleapis.com/*' => Http::response(['users' => [
            ['id' => 'g1', 'primaryEmail' => 'ada@acme.com', 'name' => ['fullName' => 'Ada Lovelace'], 'suspended' => false],
            ['id' => 'g2', 'primaryEmail' => 'bo@acme.com', 'name' => ['fullName' => 'Bo Diaz'], 'suspended' => true],
        ]]),
    ]);

    $users = iterator_to_array((new GoogleWorkspaceConnector)->fetchUsers([
        'client_email' => 'sa@project.iam.gserviceaccount.com',
        'private_key' => testRsaKey(),
        'admin_email' => 'admin@acme.com',
    ]));

    expect($users)->toHaveCount(2)
        ->and($users[0]->externalId)->toBe('g1')
        ->and($users[0]->email)->toBe('ada@acme.com')
        ->and($users[0]->displayName)->toBe('Ada Lovelace')
        ->and($users[0]->active)->toBeTrue()
        ->and($users[1]->active)->toBeFalse();
});

it('pulls and maps Microsoft Entra users across pages (disabled → inactive)', function (): void {
    Http::fake([
        'login.microsoftonline.com/*' => Http::response(['access_token' => 'graph.token']),
        'graph.microsoft.com/*' => Http::sequence()
            ->push([
                'value' => [['id' => 'e1', 'userPrincipalName' => 'ada@acme.com', 'displayName' => 'Ada', 'mail' => 'ada@acme.com', 'accountEnabled' => true]],
                '@odata.nextLink' => 'https://graph.microsoft.com/v1.0/users?$skiptoken=abc',
            ])
            ->push(['value' => [['id' => 'e2', 'userPrincipalName' => 'bo@acme.com', 'displayName' => 'Bo', 'accountEnabled' => false]]]),
    ]);

    $users = iterator_to_array((new MicrosoftEntraConnector)->fetchUsers([
        'tenant_id' => 'tenant-123', 'client_id' => 'app-id', 'client_secret' => 'shh',
    ]));

    expect($users)->toHaveCount(2)
        ->and($users[0]->externalId)->toBe('e1')
        ->and($users[0]->email)->toBe('ada@acme.com')
        ->and($users[0]->active)->toBeTrue()
        // Entra user with no `mail` falls back to the UPN.
        ->and($users[1]->email)->toBe('bo@acme.com')
        ->and($users[1]->active)->toBeFalse();
});

it('pulls Google Workspace groups with their user members', function (): void {
    Http::fake([
        'oauth2.googleapis.com/token' => Http::response(['access_token' => 'ya29.token']),
        'admin.googleapis.com/admin/directory/v1/groups/grp1/members*' => Http::response(['members' => [
            ['id' => 'g1', 'type' => 'USER'],
            ['id' => 'nested', 'type' => 'GROUP'],
        ]]),
        'admin.googleapis.com/admin/directory/v1/groups*' => Http::response(['groups' => [
            ['id' => 'grp1', 'name' => 'Engineering', 'email' => 'eng@acme.com'],
        ]]),
    ]);

    $groups = iterator_to_array((new GoogleWorkspaceConnector)->fetchGroups([
        'client_email' => 'sa@x.iam', 'private_key' => testRsaKey(), 'admin_email' => 'admin@acme.com',
    ]));

    expect($groups)->toHaveCount(1)
        ->and($groups[0]->externalId)->toBe('grp1')
        ->and($groups[0]->displayName)->toBe('Engineering')
        // Only USER members; the nested GROUP is excluded.
        ->and($groups[0]->memberExternalIds)->toBe(['g1']);
});

it('reconciles groups, resolving members to directory users', function (): void {
    $org = app(Organizations::class)->create(new NewOrganization('Acme', 'acme'));

    $fake = (new FakeDirectoryConnector(DirectoryProvider::GoogleWorkspace, [
        new ScimUser(externalId: 'u1', userName: 'a@acme.com', email: 'a@acme.com'),
        new ScimUser(externalId: 'u2', userName: 'b@acme.com', email: 'b@acme.com'),
    ]))->returnsGroups([
        new DirectoryGroupSnapshot('grp1', 'Engineering', ['u1', 'u2', 'ghost']),
    ]);
    app()->instance(DirectoryConnectors::class, new DirectoryConnectors([$fake]));

    $directory = app(Directories::class)->registerPull($org->id, 'Google', DirectoryProvider::GoogleWorkspace, [
        'client_email' => 'x', 'private_key' => 'y', 'admin_email' => 'z',
    ]);

    $result = app(DirectoryPullSync::class)->sync($directory);

    expect($result->groupsSynced)->toBe(1);
    $group = DirectoryGroup::query()->where('directory_id', $directory->id)->where('external_id', 'grp1')->first();
    expect($group)->not->toBeNull()
        ->and($group->display_name)->toBe('Engineering');
});

it('reconciles a pull: provisions users then deprovisions leavers', function (): void {
    $org = app(Organizations::class)->create(new NewOrganization('Acme', 'acme'));

    $fake = new FakeDirectoryConnector(DirectoryProvider::GoogleWorkspace, [
        new ScimUser(externalId: 'u1', userName: 'a@acme.com', email: 'a@acme.com', displayName: 'A'),
        new ScimUser(externalId: 'u2', userName: 'b@acme.com', email: 'b@acme.com', displayName: 'B'),
    ]);
    app()->instance(DirectoryConnectors::class, new DirectoryConnectors([$fake]));

    $directory = app(Directories::class)->registerPull($org->id, 'Google', DirectoryProvider::GoogleWorkspace, [
        'client_email' => 'x', 'private_key' => 'y', 'admin_email' => 'z',
    ]);

    // First pull: both users provisioned.
    $result = app(DirectoryPullSync::class)->sync($directory);
    expect($result->provisioned)->toBe(2)
        ->and($result->deprovisioned)->toBe(0)
        ->and(DirectoryUser::query()->where('directory_id', $directory->id)->where('active', true)->count())->toBe(2)
        ->and($directory->fresh()->last_synced_at)->not->toBeNull();

    // u2 leaves the provider → second pull deprovisions exactly u2.
    $fake->returns([new ScimUser(externalId: 'u1', userName: 'a@acme.com', email: 'a@acme.com')]);
    $result = app(DirectoryPullSync::class)->sync($directory);
    expect($result->provisioned)->toBe(1)
        ->and($result->deprovisioned)->toBe(1);
});

it('runs the scheduled sync command across pull directories', function (): void {
    $org = app(Organizations::class)->create(new NewOrganization('Acme', 'acme'));
    $fake = new FakeDirectoryConnector(DirectoryProvider::GoogleWorkspace, [
        new ScimUser(externalId: 'u1', userName: 'a@acme.com', email: 'a@acme.com'),
    ]);
    app()->instance(DirectoryConnectors::class, new DirectoryConnectors([$fake]));

    $directory = app(Directories::class)->registerPull($org->id, 'Google', DirectoryProvider::GoogleWorkspace, [
        'client_email' => 'x', 'private_key' => 'y', 'admin_email' => 'z',
    ]);

    $this->artisan('cbox-id:directory:sync')->assertSuccessful();

    expect(DirectoryUser::query()->where('directory_id', $directory->id)->where('active', true)->count())->toBe(1);
});

it('records the failure reason when a connector cannot connect', function (): void {
    $org = app(Organizations::class)->create(new NewOrganization('Acme', 'acme'));

    Http::fake(['oauth2.googleapis.com/token' => Http::response(['error' => 'invalid_grant'], 400)]);

    $directory = app(Directories::class)->registerPull($org->id, 'Google', DirectoryProvider::GoogleWorkspace, [
        'client_email' => 'x', 'private_key' => testRsaKey(), 'admin_email' => 'z',
    ]);

    expect(fn () => app(DirectoryPullSync::class)->sync($directory))->toThrow(DirectoryConnectionFailed::class);
    expect($directory->fresh()->last_sync_error)->toContain('Google Workspace');
});
