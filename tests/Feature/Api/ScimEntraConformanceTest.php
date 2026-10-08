<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Microsoft Entra ID, replayed.
 *
 * Every request below is the shape Microsoft documents its provisioning service sending
 * ("Tutorial: Develop and plan provisioning for a SCIM endpoint in Microsoft Entra ID",
 * and "Known issues … SCIM 2.0 protocol compliance" for the with/without-flag variants),
 * and every test is named after the Entra SCIM Validator check it mirrors. Bodies are
 * kept verbatim — capitalised `op`s, the extra ADSCIM schema URN on groups, `$ref: null`
 * on members, `"active": "False"` — because those quirks are the point.
 */
const ENTRA_ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
});

/**
 * The "Create User" request body, verbatim.
 *
 * @return array<string, mixed>
 */
function entraUser(string $suffix = '00aa00aa-bb11-cc22-dd33-44ee44ee44ee', string $externalId = '0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef'): array
{
    return [
        'schemas' => [
            'urn:ietf:params:scim:schemas:core:2.0:User',
            'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'],
        'externalId' => $externalId,
        'userName' => 'Test_User_'.$suffix,
        'active' => true,
        'emails' => [[
            'primary' => true,
            'type' => 'work',
            'value' => 'Test_User_'.$suffix.'@testuser.com',
        ]],
        'meta' => ['resourceType' => 'User'],
        'name' => [
            'formatted' => 'givenName familyName',
            'familyName' => 'familyName',
            'givenName' => 'givenName',
        ],
        'roles' => [],
    ];
}

/**
 * @return array<string, mixed>
 */
function entraFindUser(object $test, string $filter): array
{
    $list = $test->getJson('/scim/v2/Users?filter='.rawurlencode($filter), $test->scimHeaders)
        ->assertOk()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:ListResponse')
        ->assertJsonPath('totalResults', 1)
        ->json('Resources.0');

    expect($list)->toBeArray();

    return $list;
}

// ---------------------------------------------------------------------------
// User operations
// ---------------------------------------------------------------------------

it('Create New User: 201 with an id, then found by the joining property', function (): void {
    $created = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)
        ->assertCreated()
        ->assertHeader('Content-Type', 'application/scim+json');

    expect($created->json('id'))->toBeString()->not->toBe('');

    $found = entraFindUser($this, 'userName eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee"');

    expect($found['id'])->toBe($created->json('id'))
        ->and($found['externalId'])->toBe('0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef')
        ->and($found['active'])->toBeTrue()
        ->and($found['name'])->toBe(['formatted' => 'givenName familyName', 'givenName' => 'givenName', 'familyName' => 'familyName'])
        ->and($found['emails'][0]['value'])->toBe('Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee@testuser.com');
});

it('Create Duplicate User: 201, then 409 on the identical payload', function (): void {
    $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->assertCreated();

    $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)
        ->assertStatus(409)
        ->assertJsonPath('scimType', 'uniqueness')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');

    $this->getJson('/scim/v2/Users', $this->scimHeaders)->assertJsonPath('totalResults', 1);
});

it('Get User, and 404 with a SCIM error for one that does not exist', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('id', $id);

    $this->getJson('/scim/v2/Users/5171a35d82074e068ce2', $this->scimHeaders)
        ->assertNotFound()
        ->assertJsonPath('status', '404')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');
});

it('Get User by query, and by query with zero results', function (): void {
    $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->assertCreated();

    entraFindUser($this, 'userName eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee"');

    $this->getJson('/scim/v2/Users?filter='.rawurlencode('userName eq "non-existent user"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:ListResponse')
        ->assertJsonPath('totalResults', 0)
        ->assertJsonPath('Resources', []);
});

it('queries a user by externalId, the matching attribute of the provisioning service', function (): void {
    $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->assertCreated();

    entraFindUser($this, 'externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"');
});

it('queries a user by the work email when uniqueness is keyed on it', function (): void {
    $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->assertCreated();

    // "a GET to /Users with a filter must allow for both userName eq … and
    // emails[type eq "work"].value eq … queries."
    entraFindUser($this, 'emails[type eq "work"].value eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee@testuser.com"');
});

it('Update User [Multi-valued properties]: Replace the work email and familyName', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            [
                'op' => 'Replace',
                'path' => 'emails[type eq "work"].value',
                'value' => 'updatedEmail@microsoft.com',
            ],
            [
                'op' => 'Replace',
                'path' => 'name.familyName',
                'value' => 'updatedFamilyName',
            ],
        ],
    ], $this->scimHeaders)->assertOk();

    $found = entraFindUser($this, 'userName eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee"');

    expect($found['emails'][0]['value'])->toBe('updatedEmail@microsoft.com')
        ->and($found['name']['familyName'])->toBe('updatedFamilyName')
        ->and($found['name']['givenName'])->toBe('givenName');
});

it('Update Joining Property: Replace userName, then find the user by the new value', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'Replace',
            'path' => 'userName',
            'value' => '5b50642d-79fc-4410-9e90-4c077cdd1a59@testuser.com',
        ]],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('userName', '5b50642d-79fc-4410-9e90-4c077cdd1a59@testuser.com');

    expect(entraFindUser($this, 'userName eq "5b50642d-79fc-4410-9e90-4c077cdd1a59@testuser.com"')['id'])->toBe($id);
});

it('Add Attributes: an add of non-required attributes, then present on the user', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    // Without the compliance flag Entra sends `Add` (and even attributes this server
    // does not store, like nickName — accepted, not refused).
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'Add', 'path' => 'displayName', 'value' => 'Babs Jensen'],
            ['op' => 'Add', 'path' => 'nickName', 'value' => 'Babs'],
            ['op' => 'Add', 'path' => ENTRA_ENTERPRISE.':department', 'value' => 'Tour Operations'],
        ],
    ], $this->scimHeaders)->assertOk();

    $found = entraFindUser($this, 'userName eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee"');

    expect($found['displayName'])->toBe('Babs Jensen')
        ->and($found[ENTRA_ENTERPRISE]['department'])->toBe('Tour Operations');
});

it('Replace User Attributes: the multi-attribute replace, with and without the compliance flag', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    // Without the flag: one capitalised Replace per attribute.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'Replace', 'path' => 'displayName', 'value' => 'Pvlo'],
            ['op' => 'Replace', 'path' => 'emails[type eq "work"].value', 'value' => 'TestBcwqnm@test.microsoft.com'],
            ['op' => 'Replace', 'path' => 'name.givenName', 'value' => 'Gtfd'],
            ['op' => 'Replace', 'path' => 'name.familyName', 'value' => 'Pkqf'],
            ['op' => 'Replace', 'path' => ENTRA_ENTERPRISE.':employeeNumber', 'value' => 'Eqpj'],
        ],
    ], $this->scimHeaders)->assertOk();

    $found = entraFindUser($this, 'externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"');

    expect($found['displayName'])->toBe('Pvlo')
        ->and($found['emails'][0]['value'])->toBe('TestBcwqnm@test.microsoft.com')
        ->and($found['name']['givenName'])->toBe('Gtfd')
        ->and($found[ENTRA_ENTERPRISE]['employeeNumber'])->toBe('Eqpj');

    // With the flag (`aadOptscim062020`): the email by path, the rest pathless with
    // dotted and URN-qualified keys.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'replace', 'path' => 'emails[type eq "work"].value', 'value' => 'TestMhvaes@test.microsoft.com'],
            ['op' => 'replace', 'value' => [
                'displayName' => 'Bjfe',
                'name.givenName' => 'Kkom',
                'name.familyName' => 'Unua',
                ENTRA_ENTERPRISE.':employeeNumber' => 'Aklq',
            ]],
        ],
    ], $this->scimHeaders)->assertOk();

    $found = entraFindUser($this, 'externalId eq "0a21f0f2-8d2a-4f8e-bf98-7363c4aed4ef"');

    expect($found['displayName'])->toBe('Bjfe')
        ->and($found['emails'][0]['value'])->toBe('TestMhvaes@test.microsoft.com')
        ->and($found['name'])->toMatchArray(['givenName' => 'Kkom', 'familyName' => 'Unua'])
        ->and($found[ENTRA_ENTERPRISE]['employeeNumber'])->toBe('Aklq');
});

it('Update Active Attribute to False: both the string "False" and the boolean', function (array $operation): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [$operation],
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    ], $this->scimHeaders)->assertOk();

    // "Disabled user should be returned on GET request" with ACTIVE=FALSE.
    expect(entraFindUser($this, 'userName eq "Test_User_00aa00aa-bb11-cc22-dd33-44ee44ee44ee"')['active'])->toBeFalse();

    // Soft-deleted users come back with active=true when restored.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'Replace', 'path' => 'active', 'value' => 'True']],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('active', true);
})->with([
    'without the compliance flag' => [['op' => 'Replace', 'path' => 'active', 'value' => 'False']],
    'with the compliance flag' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
]);

it('sets and checks the manager the way Entra does', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');
    $manager = $this->postJson('/scim/v2/Users', entraUser('manager', 'mgr-external'), $this->scimHeaders)->json('id');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'Add',
            'path' => 'manager',
            'value' => [[
                '$ref' => 'http://localhost/scim/Users/'.$manager,
                'value' => $manager,
            ]],
        ]],
    ], $this->scimHeaders)->assertOk();

    // "determine whether the manager attribute of a user object currently has a
    // certain value": an id equality and a manager equality.
    entraFindUser($this, 'id eq "'.$id.'" and manager eq "'.$manager.'"');

    $this->getJson('/scim/v2/Users?filter='.rawurlencode('id eq "'.$id.'" and manager eq "someone-else"'), $this->scimHeaders)
        ->assertJsonPath('totalResults', 0);
});

it('Delete User: 204', function (): void {
    $id = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');

    $this->delete('/scim/v2/Users/'.$id, [], $this->scimHeaders)->assertNoContent();
});

// ---------------------------------------------------------------------------
// Group operations
// ---------------------------------------------------------------------------

/**
 * The "Create Group" request body, verbatim — including the second, non-SCIM schema URN.
 *
 * @return array<string, mixed>
 */
function entraGroup(): array
{
    return [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group', 'http://schemas.microsoft.com/2006/11/ResourceManagement/ADSCIM/2.0/Group'],
        'externalId' => '8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159',
        'displayName' => 'displayName',
        'meta' => [
            'resourceType' => 'Group',
        ],
    ];
}

it('Create New Group: 201 with an id and an empty member list, then found by displayName', function (): void {
    $created = $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)
        ->assertCreated()
        ->assertJsonPath('displayName', 'displayName')
        ->assertJsonPath('externalId', '8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159')
        ->assertJsonPath('members', []);

    $this->getJson('/scim/v2/Groups?excludedAttributes=members&filter='.rawurlencode('displayName eq "displayName"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.id', $created->json('id'))
        ->assertJsonMissingPath('Resources.0.members');
});

it('Create Duplicate Group: 201, then 409 on the identical payload', function (): void {
    $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)->assertCreated();

    $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)
        ->assertStatus(409)
        ->assertJsonPath('scimType', 'uniqueness');
});

it('Get Group with excludedAttributes=members', function (): void {
    $id = $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)->json('id');

    $this->getJson('/scim/v2/Groups/'.$id.'?excludedAttributes=members', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('id', $id)
        ->assertJsonPath('displayName', 'displayName')
        ->assertJsonMissingPath('members');

    $this->getJson('/scim/v2/Groups/40734ae655284ad3abcc?excludedAttributes=members', $this->scimHeaders)->assertNotFound();
});

it('queries a group by externalId, which Entra does on every cycle', function (): void {
    $id = $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)->json('id');

    $this->getJson('/scim/v2/Groups?excludedAttributes=members&filter='.rawurlencode('externalId eq "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159"'), $this->scimHeaders)
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.id', $id);
});

it('Update Group Attributes: Replace displayName, then found by the new name', function (): void {
    $id = $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'Replace',
            'path' => 'displayName',
            'value' => '1879db59-3bdf-4490-ad68-ab880a269474updatedDisplayName',
        ]],
    ], $this->scimHeaders)->assertSuccessful();

    $this->getJson('/scim/v2/Groups?excludedAttributes=members&filter='.rawurlencode('displayName eq "1879db59-3bdf-4490-ad68-ab880a269474updatedDisplayName"'), $this->scimHeaders)
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.id', $id);
});

it('Update Group [Add Members] and [Remove Members], with and without the compliance flag', function (): void {
    $group = $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)->json('id');
    $member = $this->postJson('/scim/v2/Users', entraUser(), $this->scimHeaders)->json('id');
    $other = $this->postJson('/scim/v2/Users', entraUser('other', 'other-external'), $this->scimHeaders)->json('id');

    foreach ([$member, $other] as $id) {
        $this->patchJson('/scim/v2/Groups/'.$group, [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [[
                'op' => 'Add',
                'path' => 'members',
                'value' => [[
                    '$ref' => null,
                    'value' => $id,
                ]],
            ]],
        ], $this->scimHeaders)->assertSuccessful();
    }

    $this->getJson('/scim/v2/Groups/'.$group, $this->scimHeaders)->assertJsonCount(2, 'members');

    // Membership check: the group, with this member.
    $this->getJson('/scim/v2/Groups?excludedAttributes=members&filter='.rawurlencode('id eq "'.$group.'" and members[value eq "'.$member.'"]'), $this->scimHeaders)
        ->assertJsonPath('totalResults', 1);

    // Without the flag: Remove on `members` with a value list.
    $this->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'Remove',
            'path' => 'members',
            'value' => [[
                '$ref' => null,
                'value' => $member,
            ]],
        ]],
    ], $this->scimHeaders)->assertSuccessful();

    $this->getJson('/scim/v2/Groups/'.$group, $this->scimHeaders)
        ->assertJsonCount(1, 'members')
        ->assertJsonPath('members.0.value', $other);

    // With the flag: a value-filter path.
    $this->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'remove',
            'path' => 'members[value eq "'.$other.'"]',
        ]],
    ], $this->scimHeaders)->assertSuccessful();

    $this->getJson('/scim/v2/Groups/'.$group, $this->scimHeaders)->assertJsonPath('members', []);
});

it('Delete Group: 204, then 404', function (): void {
    $id = $this->postJson('/scim/v2/Groups', entraGroup(), $this->scimHeaders)->json('id');

    $this->delete('/scim/v2/Groups/'.$id, [], $this->scimHeaders)->assertNoContent();
    $this->getJson('/scim/v2/Groups/'.$id, $this->scimHeaders)->assertNotFound();
});

it('Discover schema: /Schemas is a ListResponse', function (): void {
    $this->getJson('/scim/v2/Schemas', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:ListResponse')
        ->assertJsonPath('Resources.0.id', 'urn:ietf:params:scim:schemas:core:2.0:User');
});
