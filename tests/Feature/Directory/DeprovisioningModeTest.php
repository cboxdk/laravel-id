<?php

declare(strict_types=1);

use Cbox\Id\Directory\Contracts\DeprovisioningPolicy;
use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\Contracts\DirectorySync;
use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Directory\DirectoryPullSync;
use Cbox\Id\Directory\Enums\DeprovisioningMode;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Testing\FakeDirectoryConnector;
use Cbox\Id\Directory\ValueObjects\ScimUser;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * WHOSE IS THE ACCOUNT.
 *
 * A directory that stops listing a person used to deactivate their account, always. In an
 * environment one customer owns that is right. In one many organizations share it lets a
 * single employer lock a person out of every other organization they belong to — so the
 * environment says how far a deprovision reaches, and `membership` stops at the membership.
 *
 * Every way a directory lets go of someone is covered in both modes: SCIM DELETE,
 * `active: false` by PATCH and by PUT, and a pull sync that no longer sees them.
 */

/** The test environment's row, carrying the mode the way a host would store it. */
function deprovisioningEnvironment(?string $mode): void
{
    Environment::query()->create([
        'id' => 'env_test',
        'name' => 'Test',
        'slug' => 'test',
        'settings' => $mode === null ? [] : ['directory' => ['deprovisioning' => $mode]],
    ]);
}

/**
 * A person in two organizations, pushed by the first one's SCIM directory, signed in to
 * each of them and once to neither.
 *
 * @return array{headers: array<string, string>, scimId: string, userId: string, employer: string, other: string, sessions: array{employer: string, other: string, own: string}}
 */
function sharedPerson(object $test): array
{
    // The harness's factories are protected, so they are called as the test itself.
    [$employer, $other, $token] = (function (): array {
        $employer = $this->makeOrganization('Employer');

        return [$employer, $this->makeOrganization('Other'), $this->makeDirectory($employer->id)->token];
    })->call($test);
    $headers = ['Authorization' => 'Bearer '.$token];

    $scimId = (string) $test->postJson('/scim/v2/Users', [
        'userName' => 'dana',
        'externalId' => 'okta|1',
        'emails' => [['value' => 'dana@corp.com', 'primary' => true]],
        'active' => true,
    ], $headers)->assertCreated()->json('id');

    $userId = (string) app(Subjects::class)->findByEmail('dana@corp.com')?->id;
    app(Memberships::class)->add($other->id, $userId, MembershipRole::Member);

    $sessions = app(SessionManager::class);

    return [
        'headers' => $headers,
        'scimId' => $scimId,
        'userId' => $userId,
        'employer' => $employer->id,
        'other' => $other->id,
        'sessions' => [
            'employer' => $sessions->start($userId, $employer->id, ['sso'])->id,
            'other' => $sessions->start($userId, $other->id, ['pwd'])->id,
            'own' => $sessions->start($userId, null, ['pwd'])->id,
        ],
    ];
}

/** What `membership` mode promises: the employer is gone, the person is not. */
function expectOnlyTheMembershipEnded(array $person): void
{
    $sessions = app(SessionManager::class);

    expect(app(Subjects::class)->isActive($person['userId']))->toBeTrue()
        ->and(app(Memberships::class)->of($person['employer'], $person['userId']))->toBeNull()
        ->and(app(Memberships::class)->of($person['other'], $person['userId']))->not->toBeNull()
        ->and($sessions->active($person['sessions']['employer']))->toBeNull()
        ->and($sessions->active($person['sessions']['other']))->not->toBeNull()
        ->and($sessions->active($person['sessions']['own']))->not->toBeNull()
        ->and(AuditEntry::query()->where('action', 'user.deactivated')->exists())->toBeFalse()
        // The removal event is what withdraws the organization's tokens (see
        // WithdrawAccessOnMembershipRemoval), so it has to have been raised.
        ->and(AuditEntry::query()->where('action', 'organization.member_removed')->where('organization_id', $person['employer'])->exists())->toBeTrue();
}

/** What `account` mode has always done. */
function expectTheAccountEnded(array $person): void
{
    $sessions = app(SessionManager::class);

    expect(app(Subjects::class)->isActive($person['userId']))->toBeFalse()
        ->and(app(Memberships::class)->of($person['employer'], $person['userId']))->toBeNull()
        ->and($sessions->active($person['sessions']['employer']))->toBeNull()
        ->and($sessions->active($person['sessions']['other']))->toBeNull()
        ->and($sessions->active($person['sessions']['own']))->toBeNull();
}

dataset('ways a SCIM directory lets go', [
    'DELETE' => [fn (object $test, array $p) => $test->deleteJson('/scim/v2/Users/'.$p['scimId'], [], $p['headers'])->assertNoContent()],
    'PATCH active:false' => [fn (object $test, array $p) => $test->patchJson('/scim/v2/Users/'.$p['scimId'], [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
    ], $p['headers'])->assertOk()->assertJsonPath('active', false)],
    'PUT active:false' => [fn (object $test, array $p) => $test->putJson('/scim/v2/Users/'.$p['scimId'], [
        'userName' => 'dana',
        'externalId' => 'okta|1',
        'emails' => [['value' => 'dana@corp.com', 'primary' => true]],
        'active' => false,
    ], $p['headers'])->assertOk()->assertJsonPath('active', false)],
]);

it('ends only the organization’s membership in membership mode', function (Closure $letGo): void {
    deprovisioningEnvironment('membership');
    $person = sharedPerson($this);

    $letGo($this, $person);

    expectOnlyTheMembershipEnded($person);
})->with('ways a SCIM directory lets go')->group('security');

it('deactivates the account in account mode, as it always has', function (Closure $letGo): void {
    deprovisioningEnvironment('account');
    $person = sharedPerson($this);

    $letGo($this, $person);

    expectTheAccountEnded($person);
})->with('ways a SCIM directory lets go')->group('security');

it('defaults to account mode when the environment says nothing', function (): void {
    // No environment row at all (a host that never stored one) and no setting on it: an
    // existing tenant environment must behave exactly as before the mode existed.
    $person = sharedPerson($this);

    $this->deleteJson('/scim/v2/Users/'.$person['scimId'], [], $person['headers'])->assertNoContent();

    expectTheAccountEnded($person);
})->group('security');

it('takes the deployment default from config, and lets the environment override it', function (): void {
    config(['cbox-id.directory.deprovisioning' => 'membership']);
    $directory = $this->makeDirectory($this->makeOrganization()->id)->directory;
    $policy = app(DeprovisioningPolicy::class);

    expect($policy->modeFor($directory))->toBe(DeprovisioningMode::Membership);

    deprovisioningEnvironment('account');
    expect($policy->modeFor($directory))->toBe(DeprovisioningMode::Account);

    // A value that is not a mode is not a mode: it falls through, it does not pick one.
    Environment::query()->whereKey('env_test')->firstOrFail()->update(['settings' => ['directory' => ['deprovisioning' => 'memberships']]]);
    config(['cbox-id.directory.deprovisioning' => 'nonsense']);
    expect($policy->modeFor($directory))->toBe(DeprovisioningMode::Account);
});

it('says in the event and the audit entry how far the deprovision reached', function (string $mode, bool $accountDeactivated): void {
    deprovisioningEnvironment($mode);
    $person = sharedPerson($this);

    $this->deleteJson('/scim/v2/Users/'.$person['scimId'], [], $person['headers'])->assertNoContent();

    $entry = AuditEntry::query()->where('action', 'directory.user.deprovisioned')->sole();

    expect($entry->context)->toMatchArray([
        'user_id' => $person['userId'],
        'reason' => 'directory_removed',
        'deprovisioning' => $mode,
        'account_deactivated' => $accountDeactivated,
    ]);
})->with([['membership', false], ['account', true]]);

it('never reactivates an account from a directory in membership mode', function (): void {
    // The other half of "the account is the person's own": a directory that cannot
    // disable an account cannot bring back one that somebody else disabled.
    deprovisioningEnvironment('membership');
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $sync = app(DirectorySync::class);

    $userId = (string) $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'))->user_id;
    app(Subjects::class)->deactivate($userId);

    $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com', active: true));

    expect(app(Subjects::class)->isActive($userId))->toBeFalse();
})->group('security');

it('gives the membership back when the directory lists the person again', function (): void {
    deprovisioningEnvironment('membership');
    $org = $this->makeOrganization();
    $directory = $this->makeDirectory($org->id)->directory;
    $sync = app(DirectorySync::class);

    $userId = (string) $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com'))->user_id;
    $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com', active: false));
    expect(app(Memberships::class)->of($org->id, $userId))->toBeNull();

    $sync->provisionUser($directory->id, new ScimUser('okta|1', 'dana', 'dana@corp.com', active: true));

    expect(app(Memberships::class)->of($org->id, $userId))->not->toBeNull()
        ->and(app(Subjects::class)->isActive($userId))->toBeTrue();
});

it('ends only the membership when a pull sync no longer sees the person', function (string $mode, bool $accountSurvives): void {
    deprovisioningEnvironment($mode);
    $org = $this->makeOrganization();

    $fake = new FakeDirectoryConnector(DirectoryProvider::GoogleWorkspace, [
        new ScimUser(externalId: 'u1', userName: 'a@acme.com', email: 'a@acme.com'),
        new ScimUser(externalId: 'u2', userName: 'b@acme.com', email: 'b@acme.com'),
    ]);
    app()->instance(DirectoryConnectors::class, new DirectoryConnectors([$fake]));

    $directory = app(Directories::class)->registerPull($org->id, 'Google', DirectoryProvider::GoogleWorkspace, [
        'client_email' => 'x', 'private_key' => 'y', 'admin_email' => 'z',
    ]);

    app(DirectoryPullSync::class)->sync($directory);
    $leaver = (string) app(Subjects::class)->findByEmail('b@acme.com')?->id;
    $stayer = (string) app(Subjects::class)->findByEmail('a@acme.com')?->id;

    $fake->returns([new ScimUser(externalId: 'u1', userName: 'a@acme.com', email: 'a@acme.com')]);
    $result = app(DirectoryPullSync::class)->sync($directory);

    expect($result->deprovisioned)->toBe(1)
        ->and(app(Memberships::class)->of($org->id, $leaver))->toBeNull()
        ->and(app(Subjects::class)->isActive($leaver))->toBe($accountSurvives)
        ->and(app(Memberships::class)->of($org->id, $stayer))->not->toBeNull()
        ->and(app(Subjects::class)->isActive($stayer))->toBeTrue();
})->with([['membership', true], ['account', false]])->group('security');
