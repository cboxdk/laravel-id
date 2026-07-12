<?php

declare(strict_types=1);

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('registers a directory and reveals its bearer token once', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeDirectory($org->id);

    expect($registered->token)->toStartWith('scim_')
        ->and($registered->directory->bearer_token_hash)->not->toBe($registered->token)
        ->and(app(Directories::class)->authenticate($registered->token)?->id)->toBe($registered->directory->id)
        ->and(app(Directories::class)->authenticate('scim_wrong'))->toBeNull();
});

it('provisions a SCIM user into a local user + membership', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;

    $directoryUser = app(DirectorySync::class)->provisionUser(
        $directory->id,
        new ScimUser('okta|1', 'dana', 'dana@corp.com', 'Dana'),
    );

    expect($directoryUser->user_id)->not->toBeNull()
        ->and($directoryUser->active)->toBeTrue()
        ->and(app(UserDirectory::class)->findByEmail('dana@corp.com'))->not->toBeNull()
        ->and(app(Memberships::class)->of($org->id, (string) $directoryUser->user_id))->not->toBeNull();
});

it('is idempotent per external id', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $sync = app(DirectorySync::class);

    $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'));
    $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com', 'Dana Updated'));

    expect(DirectoryUser::query()->count())->toBe(1);
});

it('revokes sessions and membership when a user is deprovisioned', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $sync = app(DirectorySync::class);

    $directoryUser = $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'));
    $userId = (string) $directoryUser->user_id;
    $session = app(SessionManager::class)->start($userId, $org->id, ['sso']);

    $sync->deprovisionUser($directory->id, 'okta|1');

    expect(app(SessionManager::class)->active($session->id))->toBeNull()          // sessions killed
        ->and(app(Memberships::class)->of($org->id, $userId))->toBeNull()          // membership dropped
        ->and(DirectoryUser::query()->firstOrFail()->active)->toBeFalse();
});

it('deactivation (active=false) also revokes access', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $sync = app(DirectorySync::class);

    $directoryUser = $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'));
    $userId = (string) $directoryUser->user_id;
    $session = app(SessionManager::class)->start($userId, $org->id, ['sso']);

    $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com', active: false));

    expect(app(SessionManager::class)->active($session->id))->toBeNull()
        ->and(app(Memberships::class)->of($org->id, $userId))->toBeNull();
});

it('emits an event and records audit on provisioning', function (): void {
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    app(DirectorySync::class)->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'));

    $events->assertEmitted('directory.user.provisioned');
    $audit->assertRecorded('directory.user.provisioned');
});
