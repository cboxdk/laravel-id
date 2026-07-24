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

it('replaces members via a pathless PATCH replace without wiping them (Azure/Entra shape)', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering', 'externalId' => 'grp|1',
        'members' => [['value' => $alice]],
    ], $headers)->json('id');

    // Pathless replace carrying the members under the resource `members` key — this is
    // the Azure/Entra shape. It previously extracted zero ids and cleared ALL members.
    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'value' => ['members' => [['value' => $bob]]]]],
    ], $headers)
        ->assertOk()
        ->assertJsonCount(1, 'members')
        ->assertJsonPath('members.0.value', $bob);

    // A pathless replace that carries NO members (a displayName-only change) must leave
    // membership intact, never fall through to a wipe.
    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'value' => ['displayName' => 'Eng']]],
    ], $headers)->assertOk()->assertJsonCount(1, 'members');
});

it('rejects a PATCH with an unknown op instead of silently succeeding', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering', 'members' => [['value' => $alice]],
    ], $headers)->json('id');

    // An unknown op used to return 200 with no change — an IdP believes its edit
    // applied when it did not. It must now be a 400 invalidSyntax.
    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'frobnicate', 'path' => 'members', 'value' => [['value' => $alice]]]],
    ], $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidSyntax');

    // Membership is untouched by the rejected op.
    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)->assertJsonCount(1, 'members');
});

it('rejects a PATCH with an unsupported path', function (): void {
    $headers = $this->scimHeaders;
    $groupId = $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $headers)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'notAScimAttribute', 'value' => 'x']],
    ], $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidPath');
});

it('rejects a PUT replacement missing the required displayName', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering', 'members' => [['value' => $alice]],
    ], $headers)->json('id');

    // PUT is a full replacement; displayName is required (RFC 7643 §4.2). A PUT
    // without it used to succeed as a no-op replace.
    $this->putJson('/scim/v2/Groups/'.$groupId, [
        'members' => [['value' => $alice]],
    ], $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidValue');

    // The group still carries its original displayName.
    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)->assertJsonPath('displayName', 'Engineering');
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
