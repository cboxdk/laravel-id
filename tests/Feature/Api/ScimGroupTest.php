<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $org = $this->makeOrganization();
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($org->id)->token];
});

/**
 * @param  array<string, string>  $headers
 */
function provisionUser(object $test, array $headers, string $userName, string $externalId): string
{
    return (string) $test->postJson('/scim/v2/Users', [
        'userName' => $userName,
        'externalId' => $externalId,
        'emails' => [['value' => $userName.'@corp.com', 'primary' => true]],
        'active' => true,
    ], $headers)->json('id');
}

it('creates a group with members and reads it back', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $create = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'externalId' => 'grp|1',
        'members' => [['value' => $alice], ['value' => $bob]],
    ], $headers)->assertStatus(201);

    $groupId = $create->json('id');

    expect($create->json('displayName'))->toBe('Engineering')
        ->and($create->json('members'))->toHaveCount(2);

    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)
        ->assertOk()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:schemas:core:2.0:Group')
        ->assertJsonPath('externalId', 'grp|1');
});

it('lists groups filtered by displayName', function (): void {
    $headers = $this->scimHeaders;
    $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $headers);
    $this->postJson('/scim/v2/Groups', ['displayName' => 'Sales'], $headers);

    $this->getJson('/scim/v2/Groups?filter='.urlencode('displayName eq "Sales"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.displayName', 'Sales');
});

it('adds and removes members via PATCH', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => [['value' => $alice]],
    ], $headers)->json('id');

    // Add bob.
    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'add', 'path' => 'members', 'value' => [['value' => $bob]]]],
    ], $headers)->assertOk()->assertJsonCount(2, 'members');

    // Remove alice by filter path.
    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'remove', 'path' => 'members[value eq "'.$alice.'"]']],
    ], $headers)
        ->assertOk()
        ->assertJsonCount(1, 'members')
        ->assertJsonPath('members.0.value', $bob);
});

it('renames a group via PATCH replace', function (): void {
    $headers = $this->scimHeaders;
    $groupId = $this->postJson('/scim/v2/Groups', ['displayName' => 'Old Name'], $headers)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'Operations' => [['op' => 'replace', 'value' => ['displayName' => 'New Name']]],
    ], $headers)
        ->assertOk()
        ->assertJsonPath('displayName', 'New Name');
});

it('replaces membership wholesale with PUT', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => [['value' => $alice]],
    ], $headers)->json('id');

    $this->putJson('/scim/v2/Groups/'.$groupId, [
        'displayName' => 'Engineering',
        'members' => [['value' => $bob]], // alice replaced by bob
    ], $headers)
        ->assertOk()
        ->assertJsonCount(1, 'members')
        ->assertJsonPath('members.0.value', $bob);
});

it('deletes a group', function (): void {
    $headers = $this->scimHeaders;
    $groupId = $this->postJson('/scim/v2/Groups', ['displayName' => 'Temp'], $headers)->json('id');

    $this->deleteJson('/scim/v2/Groups/'.$groupId, [], $headers)->assertNoContent();
    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)->assertStatus(404);
});

it('advertises the Group resource type in discovery', function (): void {
    $this->getJson('/scim/v2/ResourceTypes', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('Resources.1.endpoint', '/Groups');
});
