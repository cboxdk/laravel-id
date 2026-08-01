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

/**
 * RFC 7644 §3.5.2.2: a PATCH operation with no `path` must be refused with 400 and
 * `scimType: noTarget`. The User side has always answered that way, with the clause
 * quoted in its comment.
 *
 * The Group side admitted the empty path and let a pathless `remove` fall through to
 * detaching everything, then answered 200 — so a connector or middlebox that dropped
 * `path` on a membership reconcile emptied the group, recorded a success, and never
 * retried or alarmed. Because membership changes drive the group→role bridge, that was a
 * silent mass revocation of every role the group mapped.
 *
 * Asserting the members survive, not just the status: a 400 that emptied the group first
 * would be no better.
 */
it('refuses a pathless PATCH remove and keeps every member', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => [['value' => $alice], ['value' => $bob]],
    ], $headers)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'remove']],
    ], $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'noTarget');

    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)
        ->assertOk()
        ->assertJsonCount(2, 'members');
});

/**
 * `members[value eq "x"].display` addresses a sub-attribute of ONE member, not the
 * membership list. It passed the `members` prefix check and then arrived at
 * `sync(valueIds("Some Name"))` — and `valueIds()` of a plain string is the empty array,
 * so the branch that reads like "rename a member" detached every one of them.
 *
 * Refused rather than guessed at: this server stores no per-membership display value, so
 * there is nothing it could correctly do with the operation.
 */
it('refuses a member sub-attribute path instead of emptying the group', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => [['value' => $alice], ['value' => $bob]],
    ], $headers)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'members[value eq "'.$alice.'"].display', 'value' => 'Alice A.']],
    ], $headers)->assertStatus(400);

    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)->assertOk()->assertJsonCount(2, 'members');
});

/**
 * A pathless replace carries the WHOLE resource, so one naming both a displayName and
 * members means both. The rename branch fired first and returned, silently discarding the
 * membership — with a 200, so the connector recorded a success and never re-sent it.
 *
 * Half an operation applied and reported as all of it is worse than a refusal: the
 * directory and the IdP now disagree, and nothing will reconcile them.
 */
it('applies both halves of a pathless replace that renames and sets members', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');
    $bob = provisionUser($this, $headers, 'bob', 'okta|2');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => [['value' => $alice]],
    ], $headers)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'value' => ['displayName' => 'Platform', 'members' => [['value' => $bob]]]]],
    ], $headers)->assertOk();

    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)
        ->assertOk()
        ->assertJsonPath('displayName', 'Platform')
        ->assertJsonCount(1, 'members')
        ->assertJsonPath('members.0.value', $bob);
});

/**
 * And a rename-only pathless replace must still leave membership alone — the fall-through
 * above must not have turned every rename into a membership wipe.
 */
it('leaves members alone on a rename-only pathless replace', function (): void {
    $headers = $this->scimHeaders;
    $alice = provisionUser($this, $headers, 'alice', 'okta|1');

    $groupId = $this->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => [['value' => $alice]],
    ], $headers)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'value' => ['displayName' => 'Platform']]],
    ], $headers)->assertOk();

    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)
        ->assertOk()
        ->assertJsonPath('displayName', 'Platform')
        ->assertJsonCount(1, 'members');
});
