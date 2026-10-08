<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/**
 * PATCH (RFC 7644 §3.5.2) with paths parsed by the filter grammar and value filters
 * evaluated, across the spellings identity providers actually send.
 */
const PATCH_ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];

    $this->userId = (string) $this->postJson('/scim/v2/Users', [
        'userName' => 'dana@corp.com',
        'externalId' => 'ext-dana',
        'name' => ['givenName' => 'Dana', 'familyName' => 'Rivera'],
        'emails' => [['value' => 'dana@corp.com', 'type' => 'work', 'primary' => true]],
        PATCH_ENTERPRISE => ['department' => 'Engineering'],
    ], $this->scimHeaders)->assertCreated()->json('id');
});

/**
 * @param  list<array<string, mixed>>  $operations
 */
function patchUser(object $test, array $operations): TestResponse
{
    return $test->patchJson('/scim/v2/Users/'.$test->userId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => $operations,
    ], $test->scimHeaders);
}

it('accepts op in any case', function (string $op): void {
    patchUser($this, [['op' => $op, 'path' => 'displayName', 'value' => 'Dana '.$op]])
        ->assertOk()
        ->assertJsonPath('displayName', 'Dana '.$op);
})->with(['replace', 'Replace', 'REPLACE', 'Add', 'add']);

it('evaluates the value filter of an email path', function (string $path, bool $applies): void {
    patchUser($this, [['op' => 'Replace', 'path' => $path, 'value' => 'new@corp.com']])->assertOk();

    $this->getJson('/scim/v2/Users/'.$this->userId, $this->scimHeaders)
        ->assertJsonPath('emails.0.value', $applies ? 'new@corp.com' : 'dana@corp.com');
})->with([
    'work' => ['emails[type eq "work"].value', true],
    'work and primary' => ['emails[type eq "work" and primary eq true].value', true],
    'the current address' => ['emails[value eq "DANA@corp.com"].value', true],
    'home' => ['emails[type eq "home"].value', false],
    'not work' => ['emails[not (type eq "work")].value', false],
    'another address' => ['emails[value eq "other@corp.com"].value', false],
]);

it('accepts the whole email object under a filtered path', function (): void {
    patchUser($this, [['op' => 'add', 'path' => 'emails[type eq "work"]', 'value' => ['value' => 'obj@corp.com', 'primary' => true]]])
        ->assertOk()
        ->assertJsonPath('emails.0.value', 'obj@corp.com');
});

it('removes the stored email only when the filter selects it', function (): void {
    patchUser($this, [['op' => 'remove', 'path' => 'emails[type eq "home"]']])->assertOk()->assertJsonPath('emails.0.value', 'dana@corp.com');
    patchUser($this, [['op' => 'Remove', 'path' => 'emails[type eq "work"]']])->assertOk()->assertJsonMissingPath('emails');
});

it('accepts an addresses filter path and leaves it alone', function (): void {
    // RFC 7644 §3.5.2's own example. Addresses are not stored; the deactivation in the
    // same request still lands.
    patchUser($this, [
        ['op' => 'replace', 'path' => 'addresses[type eq "work"].streetAddress', 'value' => '1010 Broadway Ave'],
        ['op' => 'replace', 'path' => 'active', 'value' => 'False'],
    ])->assertOk()->assertJsonPath('active', false);
});

it('applies a pathless replace carrying an object, including dotted and URN keys', function (): void {
    // The shape Microsoft Entra ID sends with its compliance flag on.
    patchUser($this, [['op' => 'replace', 'value' => [
        'displayName' => 'Bjfe',
        'name.givenName' => 'Kkom',
        'name.familyName' => 'Unua',
        PATCH_ENTERPRISE.':employeeNumber' => 'Aklq',
        'active' => 'True',
    ]]])
        ->assertOk()
        ->assertJsonPath('displayName', 'Bjfe')
        ->assertJsonPath('name.givenName', 'Kkom')
        ->assertJsonPath('name.familyName', 'Unua')
        ->assertJsonPath('active', true);

    expect($this->getJson('/scim/v2/Users/'.$this->userId, $this->scimHeaders)->json()[PATCH_ENTERPRISE]['employeeNumber'])->toBe('Aklq');
});

it('addresses core attributes by their fully qualified URN', function (): void {
    patchUser($this, [
        ['op' => 'replace', 'path' => 'urn:ietf:params:scim:schemas:core:2.0:User:displayName', 'value' => 'Qualified'],
        ['op' => 'replace', 'path' => 'urn:ietf:params:scim:schemas:core:2.0:User:name.familyName', 'value' => 'Okonkwo'],
    ])->assertOk()->assertJsonPath('displayName', 'Qualified')->assertJsonPath('name.familyName', 'Okonkwo');
});

it('patches every enterprise attribute, however it is addressed', function (): void {
    $body = patchUser($this, [
        ['op' => 'replace', 'path' => PATCH_ENTERPRISE.':Department', 'value' => 'Sales'],
        ['op' => 'add', 'path' => PATCH_ENTERPRISE.':costCenter', 'value' => 'CC-7'],
        // Entra's unqualified manager, as a one-element list of {$ref, value}.
        ['op' => 'Add', 'path' => 'manager', 'value' => [['$ref' => 'https://idp.example/Users/m-1', 'value' => 'm-1']]],
    ])->assertOk()->json();

    expect($body[PATCH_ENTERPRISE])->toBe([
        'costCenter' => 'CC-7',
        'department' => 'Sales',
        'manager' => ['$ref' => 'https://idp.example/Users/m-1', 'value' => 'm-1'],
    ]);

    // A bare id, and a sub-attribute path, both land in the complex attribute.
    $body = patchUser($this, [
        ['op' => 'replace', 'path' => PATCH_ENTERPRISE.':manager', 'value' => 'm-2'],
        ['op' => 'replace', 'path' => PATCH_ENTERPRISE.':manager.displayName', 'value' => 'Grace'],
    ])->assertOk()->json();

    expect($body[PATCH_ENTERPRISE]['manager'])->toBe(['value' => 'm-2', 'displayName' => 'Grace']);

    // And they come out again.
    $body = patchUser($this, [
        ['op' => 'remove', 'path' => PATCH_ENTERPRISE.':manager.displayName'],
        ['op' => 'remove', 'path' => PATCH_ENTERPRISE.':costCenter'],
    ])->assertOk()->json();

    expect($body[PATCH_ENTERPRISE])->toBe(['department' => 'Sales', 'manager' => ['value' => 'm-2']]);
});

it('refuses an attribute the enterprise extension does not define', function (): void {
    patchUser($this, [['op' => 'replace', 'path' => PATCH_ENTERPRISE.':shoeSize', 'value' => '44']])
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidPath');
});

it('refuses a path under a schema this server does not implement', function (): void {
    patchUser($this, [['op' => 'replace', 'path' => 'urn:example:custom:2.0:User:badge', 'value' => '1']])
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidPath');
});

it('treats externalId as immutable, but accepts its current value', function (): void {
    patchUser($this, [['op' => 'Replace', 'path' => 'externalId', 'value' => 'ext-dana']])->assertOk();

    patchUser($this, [['op' => 'Replace', 'path' => 'externalId', 'value' => 'ext-other']])
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'mutability');

    $this->getJson('/scim/v2/Users/'.$this->userId, $this->scimHeaders)->assertJsonPath('externalId', 'ext-dana');
});

it('refuses a value filter on a single-valued attribute', function (): void {
    patchUser($this, [['op' => 'replace', 'path' => 'userName[value eq "x"]', 'value' => 'y']])
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidPath');
});

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/**
 * @return array{string, list<string>}
 */
function patchGroupWithMembers(object $test, int $members): array
{
    $ids = [];
    for ($i = 0; $i < $members; $i++) {
        $ids[] = (string) $test->postJson('/scim/v2/Users', ['userName' => "member{$i}@corp.com"], $test->scimHeaders)->json('id');
    }

    $group = (string) $test->postJson('/scim/v2/Groups', [
        'displayName' => 'Engineering',
        'members' => array_map(static fn (string $id): array => ['value' => $id], $ids),
    ], $test->scimHeaders)->assertCreated()->json('id');

    return [$group, $ids];
}

/**
 * @param  list<array<string, mixed>>  $operations
 * @return list<string>
 */
function patchGroupMembers(object $test, string $group, array $operations, int $status = 200): array
{
    $test->patchJson('/scim/v2/Groups/'.$group, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => $operations,
    ], $test->scimHeaders)->assertStatus($status);

    $members = array_map(static fn (array $member): string => $member['value'], $test->getJson('/scim/v2/Groups/'.$group, $test->scimHeaders)->json('members') ?? []);
    sort($members);

    return $members;
}

it('removes the members a value filter selects', function (): void {
    [$group, $ids] = patchGroupWithMembers($this, 3);

    expect(patchGroupMembers($this, $group, [['op' => 'Remove', 'path' => 'members[value eq "'.$ids[0].'" or value eq "'.$ids[1].'"]']]))
        ->toBe([$ids[2]]);
});

it('removes members selected by their display value', function (): void {
    [$group, $ids] = patchGroupWithMembers($this, 2);

    expect(patchGroupMembers($this, $group, [['op' => 'remove', 'path' => 'members[display eq "MEMBER1@corp.com"]']]))
        ->toBe([$ids[0]]);
});

it('removes members listed in value with no filter — the Entra shape', function (): void {
    [$group, $ids] = patchGroupWithMembers($this, 3);

    expect(patchGroupMembers($this, $group, [['op' => 'Remove', 'path' => 'members', 'value' => [['$ref' => null, 'value' => $ids[1]]]]]))
        ->toBe(array_values(array_diff($ids, [$ids[1]])));
});

it('replaces the whole membership — the Okta shape', function (): void {
    [$group, $ids] = patchGroupWithMembers($this, 3);

    expect(patchGroupMembers($this, $group, [['op' => 'replace', 'path' => 'members', 'value' => [['value' => $ids[2], 'display' => 'member2@corp.com']]]]))
        ->toBe([$ids[2]]);
});

it('applies an Okta remove-and-add in one request', function (): void {
    [$group, $ids] = patchGroupWithMembers($this, 2);
    $new = (string) $this->postJson('/scim/v2/Users', ['userName' => 'newcomer@corp.com'], $this->scimHeaders)->json('id');

    $expected = [$ids[1], $new];
    sort($expected);

    expect(patchGroupMembers($this, $group, [
        ['op' => 'remove', 'path' => 'members[value eq "'.$ids[0].'"]'],
        ['op' => 'add', 'path' => 'members', 'value' => [['value' => $new, 'display' => 'newcomer@corp.com']]],
    ]))->toBe($expected);
});

it('renames a group with add or replace, and sets its externalId', function (): void {
    [$group] = patchGroupWithMembers($this, 1);

    $this->patchJson('/scim/v2/Groups/'.$group, ['Operations' => [
        ['op' => 'Add', 'path' => 'displayName', 'value' => 'Platform'],
        ['op' => 'replace', 'path' => 'externalId', 'value' => 'grp-9'],
    ]], $this->scimHeaders)->assertOk()->assertJsonPath('displayName', 'Platform')->assertJsonPath('externalId', 'grp-9');

    $this->patchJson('/scim/v2/Groups/'.$group, ['Operations' => [
        ['op' => 'replace', 'path' => 'urn:ietf:params:scim:schemas:core:2.0:Group:displayName', 'value' => 'Platform Team'],
        ['op' => 'remove', 'path' => 'externalId'],
    ]], $this->scimHeaders)->assertOk()->assertJsonPath('displayName', 'Platform Team')->assertJsonMissingPath('externalId');
});

it('renames through Okta\'s pathless replace carrying id and displayName', function (): void {
    [$group] = patchGroupWithMembers($this, 2);

    expect(patchGroupMembers($this, $group, [['op' => 'replace', 'value' => ['id' => $group, 'displayName' => 'Renamed']]]))->toHaveCount(2);

    $this->getJson('/scim/v2/Groups/'.$group, $this->scimHeaders)->assertJsonPath('displayName', 'Renamed');
});

it('refuses a rename onto another group\'s name with 409', function (): void {
    [$group] = patchGroupWithMembers($this, 0);
    $this->postJson('/scim/v2/Groups', ['displayName' => 'Sales'], $this->scimHeaders)->assertCreated();

    $this->patchJson('/scim/v2/Groups/'.$group, ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Sales']]], $this->scimHeaders)
        ->assertStatus(409)
        ->assertJsonPath('scimType', 'uniqueness');

    $this->getJson('/scim/v2/Groups/'.$group, $this->scimHeaders)->assertJsonPath('displayName', 'Engineering');
});

it('refuses group paths it cannot honour, and changes nothing', function (array $operation): void {
    [$group, $ids] = patchGroupWithMembers($this, 2);

    $this->patchJson('/scim/v2/Groups/'.$group, ['Operations' => [$operation]], $this->scimHeaders)->assertStatus(400);

    expect(patchGroupMembers($this, $group, [['op' => 'add', 'path' => 'members', 'value' => []]]))->toHaveCount(2);
})->with([
    'remove displayName' => [['op' => 'remove', 'path' => 'displayName']],
    'unparsable filter' => [['op' => 'remove', 'path' => 'members[value eq]']],
    'filter on an unknown sub-attribute' => [['op' => 'remove', 'path' => 'members[nickName eq "x"]']],
    'foreign schema' => [['op' => 'replace', 'path' => 'urn:example:x:Group:owner', 'value' => 'x']],
    'pathless scalar' => [['op' => 'replace', 'value' => 'Engineering']],
]);
