<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\Testing\InteractsWithDirectory;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithDirectory::class);

/**
 * Two customers sharing ONE environment — the ordinary multi-tenant shape, and the one
 * nothing covered.
 *
 * `ScimEnvironmentIsolationTest` builds its two directories in two different
 * environments, so every 404 it asserts is produced by the environment global scope.
 * Every other SCIM test file creates exactly one directory. So the explicit
 * `where('directory_id', …)` in `DatabaseDirectoryUsers` — which, since `DirectoryUser`
 * carries no tenant scope of its own, is the ONLY thing separating two customers inside
 * one environment — could be deleted with the whole suite green.
 *
 * What that buys an attacker is not a leak at the edges: a SCIM token is a provisioning
 * credential, so customer B could read, deactivate and delete customer A's users by id,
 * and every write would be recorded as legitimate provisioning by a registered
 * directory.
 */
beforeEach(function (): void {
    // One environment. Two organizations. Two directories. Nothing else separates them.
    $this->alpha = $this->makeDirectory($this->makeOrganization('Alpha Inc')->id);
    $this->beta = $this->makeDirectory($this->makeOrganization('Beta Inc')->id);

    $this->alphaUserId = (string) $this->postJson('/scim/v2/Users', [
        'userName' => 'dana@alpha.test',
        'externalId' => 'okta|alpha-1',
        'emails' => [['value' => 'dana@alpha.test', 'primary' => true]],
        'active' => true,
    ], ['Authorization' => 'Bearer '.$this->alpha->token])->assertStatus(201)->json('id');
});

it('does not let one directory read another directory user by id', function (): void {
    $this->getJson('/scim/v2/Users/'.$this->alphaUserId, ['Authorization' => 'Bearer '.$this->beta->token])
        ->assertStatus(404)
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');

    // The positive control: the owner still reads its own user. Without this, the test
    // would pass just as well if SCIM were broken for everybody.
    $this->getJson('/scim/v2/Users/'.$this->alphaUserId, ['Authorization' => 'Bearer '.$this->alpha->token])
        ->assertStatus(200)
        ->assertJsonPath('userName', 'dana@alpha.test');
});

it('does not list or filter another directory users', function (): void {
    $this->getJson('/scim/v2/Users', ['Authorization' => 'Bearer '.$this->beta->token])
        ->assertStatus(200)
        ->assertJsonPath('totalResults', 0);

    // Filtering is a separate query, so it needs its own assertion — a filter that
    // resolves before the directory predicate is applied leaks by userName lookup.
    $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "dana@alpha.test"'), [
        'Authorization' => 'Bearer '.$this->beta->token,
    ])->assertStatus(200)->assertJsonPath('totalResults', 0);
});

it('does not let one directory deactivate or delete another directory user', function (): void {
    $this->patchJson('/scim/v2/Users/'.$this->alphaUserId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
    ], ['Authorization' => 'Bearer '.$this->beta->token])->assertStatus(404);

    $this->putJson('/scim/v2/Users/'.$this->alphaUserId, [
        'userName' => 'hijacked@beta.test',
        'active' => false,
    ], ['Authorization' => 'Bearer '.$this->beta->token])->assertStatus(404);

    $this->deleteJson('/scim/v2/Users/'.$this->alphaUserId, [], [
        'Authorization' => 'Bearer '.$this->beta->token,
    ])->assertStatus(404);

    // Refused is not the same as unchanged: assert the row itself, because a handler
    // that writes and then 404s is the failure this is really about.
    $user = DirectoryUser::query()->find($this->alphaUserId);

    expect($user)->not->toBeNull('the record was deleted by a directory that does not own it')
        ->and($user->user_name_lower)->toBe('dana@alpha.test')
        ->and($user->resource['userName'] ?? null)->toBe('dana@alpha.test', 'the record was renamed by a directory that does not own it')
        ->and($user->active)->toBeTrue('the record was deactivated by a directory that does not own it');
})->group('isolation');
