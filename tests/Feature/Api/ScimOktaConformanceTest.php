<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Okta, replayed.
 *
 * The first half mirrors Okta's "SCIM 2.0 SPEC Test" suite (the Runscope test file Okta
 * publishes for SCIM integrations) step by step, asserting exactly what each "Required
 * Test" asserts. The second half replays the requests Okta's provisioning engine sends,
 * as documented in Okta's SCIM 2.0 protocol reference: the existence check with
 * `startIndex=1&count=100`, create, PUT full replace after a GET, the pathless
 * `active:false` deactivation, and the group push (pathless rename, remove-and-add, and
 * replace of members).
 */
beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
});

/**
 * "Create Okta user with realistic values", verbatim.
 *
 * @return array<string, mixed>
 */
function oktaSpecUser(string $userName = 'Runscope7Ruth@atko.com', string $email = 'Runscope7Ruth@atko.com'): array
{
    return [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'userName' => $userName,
        'name' => ['givenName' => 'Ruth', 'familyName' => 'Runscope'],
        'emails' => [['primary' => true, 'value' => $email, 'type' => 'work']],
        'displayName' => 'Ruth Runscope',
        'active' => true,
    ];
}

/**
 * The user Okta's provisioning engine creates, verbatim (password, locale and the empty
 * groups list included).
 *
 * @return array<string, mixed>
 */
function oktaProvisionedUser(): array
{
    return [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'userName' => 'test.user@okta.local',
        'name' => [
            'givenName' => 'Test',
            'familyName' => 'User',
        ],
        'emails' => [[
            'primary' => true,
            'value' => 'test.user@okta.local',
            'type' => 'work',
        ]],
        'displayName' => 'Test User',
        'locale' => 'en-US',
        'externalId' => '00ujl29u0le5T6Aj10h7',
        'groups' => [],
        'password' => '1mz050nq',
        'active' => true,
    ];
}

// ---------------------------------------------------------------------------
// The SPEC Test suite
// ---------------------------------------------------------------------------

it('Required Test: Test Users endpoint', function (): void {
    $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)->assertCreated();

    $response = $this->getJson('/scim/v2/Users?count=1&startIndex=1', $this->scimHeaders)->assertOk();

    expect($response->json('Resources'))->not->toBeEmpty()
        ->and($response->json('schemas'))->toContain('urn:ietf:params:scim:api:messages:2.0:ListResponse')
        ->and($response->json('itemsPerPage'))->toBeInt()
        ->and($response->json('startIndex'))->toBeInt()
        ->and($response->json('totalResults'))->toBeInt()
        ->and($response->json('Resources.0.id'))->not->toBeEmpty()
        ->and($response->json('Resources.0.name.familyName'))->not->toBeEmpty()
        ->and($response->json('Resources.0.name.givenName'))->not->toBeEmpty()
        ->and($response->json('Resources.0.userName'))->not->toBeEmpty()
        ->and($response->json('Resources.0.active'))->not->toBeNull()
        ->and($response->json('Resources.0.emails.0.value'))->not->toBeEmpty();
});

it('Required Test: Get Users/{{id}}', function (): void {
    $id = $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)->json('id');

    $response = $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk();

    expect($response->json('id'))->toBe($id)
        ->and($response->json('name.familyName'))->not->toBeEmpty()
        ->and($response->json('name.givenName'))->not->toBeEmpty()
        ->and($response->json('userName'))->not->toBeEmpty()
        ->and($response->json('active'))->not->toBeNull()
        ->and($response->json('emails.0.value'))->not->toBeEmpty();
});

it('Required Test: Test invalid User by username', function (): void {
    $this->getJson('/scim/v2/Users?filter='.rawurlencode('userName eq "invalidUser@atko.com"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:ListResponse')
        ->assertJsonPath('totalResults', 0);
});

it('Required Test: Test invalid User by ID', function (): void {
    $response = $this->getJson('/scim/v2/Users/010101010101010101010', $this->scimHeaders)->assertNotFound();

    expect($response->json('detail'))->not->toBeEmpty()
        ->and($response->json('schemas'))->toContain('urn:ietf:params:scim:api:messages:2.0:Error');
});

it('Required Test: Make sure random user doesn\'t exist', function (): void {
    $this->getJson('/scim/v2/Users?filter='.rawurlencode('userName eq "Runscope7Ruth@atko.com"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 0)
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:ListResponse');
});

it('Required Test: Create Okta user with realistic values, and verify it was created', function (): void {
    $created = $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)
        ->assertStatus(201)
        ->assertJsonPath('active', true)
        ->assertJsonPath('name.familyName', 'Runscope')
        ->assertJsonPath('name.givenName', 'Ruth')
        ->assertJsonPath('userName', 'Runscope7Ruth@atko.com');

    expect($created->json('id'))->not->toBeEmpty()
        ->and($created->json('schemas'))->toContain('urn:ietf:params:scim:schemas:core:2.0:User');

    $this->getJson('/scim/v2/Users/'.$created->json('id'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('userName', 'Runscope7Ruth@atko.com')
        ->assertJsonPath('name.familyName', 'Runscope')
        ->assertJsonPath('name.givenName', 'Ruth');
});

it('Required Test: Expect failure when recreating user with same values', function (): void {
    $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)->assertCreated();

    // The suite's second POST reuses the userName as the email — the same person again.
    $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)
        ->assertStatus(409)
        ->assertJsonPath('scimType', 'uniqueness')
        ->assertJsonPath('status', '409');
});

it('Required Test: Username Case Sensitivity Check', function (): void {
    $id = $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)->json('id');

    // The suite asserts only the 200; userName is caseExact:false, so it also finds her.
    $this->getJson('/scim/v2/Users?filter='.rawurlencode('userName eq "RUNSCOPE7RUTH@ATKO.COM"'), $this->scimHeaders)
        ->assertStatus(200)
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.id', $id);
});

it('Optional Test: Verify Groups endpoint', function (): void {
    $this->getJson('/scim/v2/Groups', $this->scimHeaders)->assertStatus(200);
});

it('Required Test: Check status 401', function (): void {
    $response = $this->getJson('/scim/v2/Users?filter='.rawurlencode('userName eq "RUNSCOPE7RUTH@ATKO.COM"'), ['Authorization' => 'Bearer not-a-token'])
        ->assertStatus(401)
        ->assertJsonPath('status', '401');

    expect($response->json('detail'))->not->toBeEmpty()
        ->and($response->json('schemas'))->toContain('urn:ietf:params:scim:api:messages:2.0:Error');
});

it('Required Test: Check status 404', function (): void {
    $response = $this->getJson('/scim/v2/Users/00919288221112222', $this->scimHeaders)
        ->assertStatus(404)
        ->assertJsonPath('status', '404');

    expect($response->json('detail'))->not->toBeEmpty()
        ->and($response->json('schemas'))->toContain('urn:ietf:params:scim:api:messages:2.0:Error');
});

// ---------------------------------------------------------------------------
// The requests Okta's provisioning engine sends
// ---------------------------------------------------------------------------

it('checks for the user, creates it, and finds it again — with Okta\'s pagination', function (): void {
    $filter = 'filter='.rawurlencode('userName eq "test.user@okta.local"').'&startIndex=1&count=100';

    $this->getJson('/scim/v2/Users?'.$filter, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 0)
        ->assertJsonPath('itemsPerPage', 0)
        ->assertJsonPath('startIndex', 1)
        ->assertJsonPath('Resources', []);

    $id = $this->postJson('/scim/v2/Users', oktaProvisionedUser(), $this->scimHeaders)
        ->assertCreated()
        ->assertJsonPath('externalId', '00ujl29u0le5T6Aj10h7')
        ->json('id');

    $this->getJson('/scim/v2/Users?'.$filter, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('itemsPerPage', 1)
        ->assertJsonPath('startIndex', 1)
        ->assertJsonPath('Resources.0.id', $id);
});

it('pages through users the way Okta does, with integer counters', function (): void {
    foreach (range(1, 5) as $i) {
        $this->postJson('/scim/v2/Users', oktaSpecUser("user{$i}@atko.com", "user{$i}@atko.com"), $this->scimHeaders)->assertCreated();
    }

    // Okta's connection check asks for two.
    $this->getJson('/scim/v2/Users?startIndex=1&count=2', $this->scimHeaders)
        ->assertJsonPath('totalResults', 5)
        ->assertJsonPath('itemsPerPage', 2)
        ->assertJsonPath('startIndex', 1)
        ->assertJsonCount(2, 'Resources');

    $seen = [];
    for ($start = 1; $start <= 5; $start += 2) {
        $page = $this->getJson("/scim/v2/Users?startIndex={$start}&count=2", $this->scimHeaders)->assertOk();

        expect($page->json('startIndex'))->toBe($start)
            ->and($page->json('totalResults'))->toBe(5);

        foreach ($page->json('Resources') as $resource) {
            $seen[] = $resource['id'];
        }
    }

    // The order is consistent across requests: every user exactly once.
    expect($seen)->toHaveCount(5)->and(array_unique($seen))->toHaveCount(5);
});

it('answers count=0 with the total and no resources', function (): void {
    $this->postJson('/scim/v2/Users', oktaSpecUser(), $this->scimHeaders)->assertCreated();

    $this->getJson('/scim/v2/Users?count=0', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('itemsPerPage', 0)
        ->assertJsonPath('Resources', []);
});

it('updates with a GET followed by a full PUT', function (): void {
    $id = $this->postJson('/scim/v2/Users', oktaProvisionedUser(), $this->scimHeaders)->json('id');

    $current = $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->json();

    // Okta modifies the attributes that changed and PUTs the whole resource back —
    // including id, meta and schemas, which a server must ignore, not trip over.
    $current['name'] = ['givenName' => 'Another', 'middleName' => 'Middle', 'familyName' => 'User'];
    $current['displayName'] = 'Another User';
    $current['password'] = '1mz050nq';

    $this->putJson('/scim/v2/Users/'.$id, $current, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('id', $id)
        ->assertJsonPath('name.givenName', 'Another')
        ->assertJsonPath('displayName', 'Another User')
        ->assertJsonPath('externalId', '00ujl29u0le5T6Aj10h7');
});

it('deactivates with a pathless PATCH active:false, and reactivates', function (): void {
    $id = $this->postJson('/scim/v2/Users', oktaProvisionedUser(), $this->scimHeaders)->json('id');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'replace',
            'value' => [
                'active' => false,
            ],
        ]],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('active', false);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertJsonPath('active', false);

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'value' => ['active' => true]]],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('active', true);
});

it('pushes a group: create, list, find, rename, membership, replace, delete', function (): void {
    $alice = $this->postJson('/scim/v2/Users', oktaSpecUser('alice@atko.com', 'alice@atko.com'), $this->scimHeaders)->json('id');
    $bob = $this->postJson('/scim/v2/Users', oktaSpecUser('bob@atko.com', 'bob@atko.com'), $this->scimHeaders)->json('id');

    $group = $this->postJson('/scim/v2/Groups', [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        'displayName' => 'Test SCIMv2',
        'members' => [],
    ], $this->scimHeaders)->assertCreated()->json('id');

    $this->getJson('/scim/v2/Groups?startIndex=1&count=100', $this->scimHeaders)
        ->assertJsonPath('totalResults', 1);

    $this->getJson('/scim/v2/Groups?filter='.rawurlencode('displayName eq "Test SCIMv2"').'&startIndex=1&count=100', $this->scimHeaders)
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.id', $group);

    // Rename: a pathless replace carrying the id and the new name.
    $this->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'replace',
            'value' => [
                'id' => $group,
                'displayName' => 'Test SCIMv2 Renamed',
            ],
        ]],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('displayName', 'Test SCIMv2 Renamed');

    $this->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'add', 'path' => 'members', 'value' => [['value' => $alice, 'display' => 'alice@atko.com']]]],
    ], $this->scimHeaders)->assertOk();

    // One request that removes one member and adds another.
    $this->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            [
                'op' => 'remove',
                'path' => 'members[value eq "'.$alice.'"]',
            ],
            [
                'op' => 'add',
                'path' => 'members',
                'value' => [[
                    'value' => $bob,
                    'display' => 'bob@atko.com',
                ]],
            ],
        ],
    ], $this->scimHeaders)->assertOk();

    // A group read with no parameters includes its members.
    $this->getJson('/scim/v2/Groups/'.$group, $this->scimHeaders)
        ->assertJsonCount(1, 'members')
        ->assertJsonPath('members.0.value', $bob);

    // Replace the whole membership.
    $this->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [[
            'op' => 'replace',
            'path' => 'members',
            'value' => [
                ['value' => $alice, 'display' => 'alice@atko.com'],
                ['value' => $bob, 'display' => 'bob@atko.com'],
            ],
        ]],
    ], $this->scimHeaders)->assertOk()->assertJsonCount(2, 'members');

    // Custom app integrations update with PUT instead.
    $this->putJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
        'id' => $group,
        'displayName' => 'Test SCIMv2',
        'members' => [['value' => $alice, 'display' => 'alice@atko.com']],
    ], $this->scimHeaders)->assertOk()->assertJsonCount(1, 'members')->assertJsonPath('displayName', 'Test SCIMv2');

    $this->deleteJson('/scim/v2/Groups/'.$group, [], $this->scimHeaders)->assertNoContent();
});

it('refuses a duplicate user with a 409 SCIM error body', function (): void {
    $this->postJson('/scim/v2/Users', oktaProvisionedUser(), $this->scimHeaders)->assertCreated();

    $response = $this->postJson('/scim/v2/Users', oktaProvisionedUser(), $this->scimHeaders)
        ->assertStatus(409)
        ->assertJsonPath('status', '409')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');

    expect($response->json('detail'))->not->toBeEmpty();
});
