<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryGroup;
use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

/**
 * `/Bulk` (RFC 7644 §3.7) — the request and response shapes are the RFC's own examples.
 */
beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
});

/**
 * @param  list<array<string, mixed>>  $operations
 * @param  array<string, mixed>  $extra
 */
function bulk(object $test, array $operations, array $extra = []): TestResponse
{
    return $test->postJson('/scim/v2/Bulk', [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:BulkRequest'],
        'Operations' => $operations,
    ] + $extra, $test->scimHeaders);
}

it('creates a user and a group that references it by bulkId (§3.7.2)', function (): void {
    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'qwerty', 'data' => [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
            'userName' => 'Alice',
        ]],
        ['method' => 'POST', 'path' => '/Groups', 'bulkId' => 'ytrewq', 'data' => [
            'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:Group'],
            'displayName' => 'Tour Guides',
            'members' => [['type' => 'User', 'value' => 'bulkId:qwerty']],
        ]],
    ])->assertOk();

    $response->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:BulkResponse')
        ->assertJsonCount(2, 'Operations')
        ->assertJsonPath('Operations.0.method', 'POST')
        ->assertJsonPath('Operations.0.bulkId', 'qwerty')
        ->assertJsonPath('Operations.0.status', '201')
        ->assertJsonPath('Operations.1.bulkId', 'ytrewq')
        ->assertJsonPath('Operations.1.status', '201');

    $alice = DirectoryUser::query()->where('user_name_lower', 'alice')->firstOrFail();
    $group = DirectoryGroup::query()->where('display_name', 'Tour Guides')->firstOrFail();

    expect($response->json('Operations.0.location'))->toEndWith('/scim/v2/Users/'.$alice->id)
        ->and($response->json('Operations.1.location'))->toEndWith('/scim/v2/Groups/'.$group->id)
        ->and($response->json('Operations.0.version'))->toMatch('/^W\/"/')
        ->and($response->json('Operations.0'))->not->toHaveKey('response');

    $this->getJson('/scim/v2/Groups/'.$group->id, $this->scimHeaders)->assertJsonPath('members.0.value', $alice->id);
});

it('resolves a reference to a POST that comes later in the request', function (): void {
    bulk($this, [
        ['method' => 'POST', 'path' => '/Groups', 'bulkId' => 'g', 'data' => [
            'displayName' => 'Early', 'members' => [['value' => 'bulkId:u']],
        ]],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'u', 'data' => ['userName' => 'late']],
    ])->assertOk()
        // The response keeps request order even though the user ran first.
        ->assertJsonPath('Operations.0.bulkId', 'g')
        ->assertJsonPath('Operations.0.status', '201')
        ->assertJsonPath('Operations.1.bulkId', 'u')
        ->assertJsonPath('Operations.1.status', '201');

    $group = DirectoryGroup::query()->where('display_name', 'Early')->firstOrFail()->load('members');

    expect($group->members->pluck('id')->all())->toBe([DirectoryUser::query()->where('user_name_lower', 'late')->value('id')]);
});

it('resolves bulkId in a path and in the enterprise manager', function (): void {
    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'boss', 'data' => ['userName' => 'boss']],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'worker', 'data' => [
            'userName' => 'worker',
            'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' => ['manager' => ['value' => 'bulkId:boss']],
        ]],
        ['method' => 'PATCH', 'path' => '/Users/bulkId:worker', 'data' => [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'The Worker']],
        ]],
    ])->assertOk();

    $boss = DirectoryUser::query()->where('user_name_lower', 'boss')->value('id');
    $worker = DirectoryUser::query()->where('user_name_lower', 'worker')->firstOrFail();

    expect($worker->resource['enterprise']['manager']['value'])->toBe($boss)
        ->and($worker->resource['displayName'])->toBe('The Worker')
        ->and($response->json('Operations.2.status'))->toBe('200')
        ->and($response->json('Operations.2.location'))->toEndWith('/scim/v2/Users/'.$worker->id);
});

it('fails an unresolvable or circular reference on its own, with 409', function (): void {
    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Groups', 'bulkId' => 'a', 'data' => ['displayName' => 'A', 'members' => [['value' => 'bulkId:b']]]],
        ['method' => 'POST', 'path' => '/Groups', 'bulkId' => 'b', 'data' => ['displayName' => 'B', 'members' => [['value' => 'bulkId:a']]]],
        ['method' => 'PATCH', 'path' => '/Users/bulkId:nobody', 'data' => ['Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]]]],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'fine', 'data' => ['userName' => 'fine']],
    ])->assertOk();

    expect($response->json('Operations.0.status'))->toBe('409')
        ->and($response->json('Operations.1.status'))->toBe('409')
        ->and($response->json('Operations.2.status'))->toBe('409')
        ->and($response->json('Operations.2.response.scimType'))->toBe('invalidValue')
        ->and($response->json('Operations.3.status'))->toBe('201');
});

it('fails a reference to a POST that itself failed', function (): void {
    bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'bad', 'data' => ['displayName' => 'no userName']],
        ['method' => 'POST', 'path' => '/Groups', 'bulkId' => 'g', 'data' => ['displayName' => 'G', 'members' => [['value' => 'bulkId:bad']]]],
    ])->assertOk()
        ->assertJsonPath('Operations.0.status', '400')
        ->assertJsonPath('Operations.0.response.scimType', 'invalidValue')
        ->assertJsonMissingPath('Operations.0.location')
        ->assertJsonPath('Operations.1.status', '409');
});

it('adds, updates and removes users with versions, as in §3.7.3', function (): void {
    $bob = (string) $this->postJson('/scim/v2/Users', ['userName' => 'bob'], $this->scimHeaders)->json('id');
    $dave = $this->postJson('/scim/v2/Users', ['userName' => 'dave-old'], $this->scimHeaders);
    $gone = $this->postJson('/scim/v2/Users', ['userName' => 'gone'], $this->scimHeaders);

    $bobVersion = $this->getJson('/scim/v2/Users/'.$bob, $this->scimHeaders)->json('meta.version');

    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'qwerty', 'data' => ['userName' => 'Alice']],
        ['method' => 'PUT', 'path' => '/Users/'.$bob, 'version' => $bobVersion, 'data' => ['id' => $bob, 'userName' => 'bob', 'displayName' => 'Bob']],
        ['method' => 'PATCH', 'path' => '/Users/'.$dave->json('id'), 'version' => $dave->json('meta.version'), 'data' => [
            ['op' => 'remove', 'path' => 'nickName'],
            ['op' => 'add', 'path' => 'userName', 'value' => 'Dave'],
        ]],
        ['method' => 'DELETE', 'path' => '/Users/'.$gone->json('id'), 'version' => $gone->json('meta.version')],
    ], ['failOnErrors' => 1])->assertOk();

    expect(array_column($response->json('Operations'), 'status'))->toBe(['201', '200', '200', '204'])
        ->and(array_column($response->json('Operations'), 'method'))->toBe(['POST', 'PUT', 'PATCH', 'DELETE'])
        ->and($response->json('Operations.3.location'))->toEndWith('/scim/v2/Users/'.$gone->json('id'))
        ->and($response->json('Operations.3'))->not->toHaveKey('version')
        ->and($response->json('Operations.1.version'))->not->toBe($bobVersion);

    $this->getJson('/scim/v2/Users/'.$dave->json('id'), $this->scimHeaders)->assertJsonPath('userName', 'Dave');
    $this->getJson('/scim/v2/Users/'.$gone->json('id'), $this->scimHeaders)->assertJsonPath('active', false);
});

it('answers a stale version with 412 for that operation, and keeps going', function (): void {
    $bob = (string) $this->postJson('/scim/v2/Users', ['userName' => 'bob'], $this->scimHeaders)->json('id');

    bulk($this, [
        ['method' => 'PUT', 'path' => '/Users/'.$bob, 'version' => 'W/"3694e05e9dff591"', 'data' => ['userName' => 'bob', 'displayName' => 'Nope']],
        ['method' => 'DELETE', 'path' => '/Users/e9025315-6bea-44e1-899c-1e07454e468b'],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'x', 'data' => ['userName' => 'still-created']],
    ])->assertOk()
        ->assertJsonPath('Operations.0.status', '412')
        ->assertJsonPath('Operations.0.response.status', '412')
        ->assertJsonPath('Operations.0.location', fn (string $location): bool => str_ends_with($location, '/Users/'.$bob))
        ->assertJsonPath('Operations.1.status', '404')
        ->assertJsonPath('Operations.1.response.schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('Operations.2.status', '201');
});

it('stops after failOnErrors errors and reports only what it processed', function (): void {
    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'a', 'data' => ['userName' => 'a']],
        ['method' => 'DELETE', 'path' => '/Users/missing-1'],
        ['method' => 'DELETE', 'path' => '/Users/missing-2'],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'never', 'data' => ['userName' => 'never']],
    ], ['failOnErrors' => 2])->assertOk();

    expect(array_column($response->json('Operations'), 'status'))->toBe(['201', '404', '404'])
        ->and(DirectoryUser::query()->where('user_name_lower', 'never')->exists())->toBeFalse();
});

it('continues past every failure when failOnErrors is absent', function (): void {
    $response = bulk($this, [
        ['method' => 'DELETE', 'path' => '/Users/missing-1'],
        ['method' => 'DELETE', 'path' => '/Groups/missing-2'],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'last', 'data' => ['userName' => 'last']],
    ])->assertOk();

    expect(array_column($response->json('Operations'), 'status'))->toBe(['404', '404', '201']);
});

it('reports a duplicate create as 409 inside the bulk response', function (): void {
    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'one', 'data' => ['userName' => 'twin']],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'two', 'data' => ['userName' => 'twin']],
    ])->assertOk();

    expect($response->json('Operations.1.status'))->toBe('409')
        ->and($response->json('Operations.1.response.scimType'))->toBe('uniqueness');
});

it('refuses malformed operations one by one', function (mixed $operation, string $reason): void {
    $response = bulk($this, [
        $operation,
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'ok', 'data' => ['userName' => 'ok']],
    ])->assertOk();

    expect($response->json('Operations.0.status'))->toBe('400')
        ->and($response->json('Operations.0.response.scimType'))->toBe('invalidSyntax')
        ->and($response->json('Operations.0.response.detail'))->toContain($reason)
        ->and($response->json('Operations.1.status'))->toBe('201');
})->with([
    'unknown method' => [['method' => 'GET', 'path' => '/Users'], 'method'],
    'unknown resource type' => [['method' => 'POST', 'path' => '/Widgets', 'bulkId' => 'w', 'data' => ['x' => 1]], 'path'],
    'POST to a resource' => [['method' => 'POST', 'path' => '/Users/abc', 'bulkId' => 'p', 'data' => ['userName' => 'p']], 'POST'],
    'POST without bulkId' => [['method' => 'POST', 'path' => '/Users', 'data' => ['userName' => 'p']], 'bulkId'],
    'PUT to the collection' => [['method' => 'PUT', 'path' => '/Users', 'data' => ['userName' => 'p']], 'one resource'],
    'PUT without data' => [['method' => 'PUT', 'path' => '/Users/abc'], 'data'],
    'not an object' => ['nonsense', 'operation object'],
]);

it('refuses a bulkId used twice', function (): void {
    $response = bulk($this, [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'dup', 'data' => ['userName' => 'first']],
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'dup', 'data' => ['userName' => 'second']],
    ])->assertOk();

    expect($response->json('Operations.0.status'))->toBe('201')
        ->and($response->json('Operations.1.status'))->toBe('400')
        ->and(DirectoryUser::query()->where('user_name_lower', 'second')->exists())->toBeFalse();
});

it('refuses a request with no operations, or an invalid failOnErrors', function (array $body, string $scimType): void {
    $this->postJson('/scim/v2/Bulk', $body, $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', $scimType);
})->with([
    'no Operations' => [['schemas' => ['urn:ietf:params:scim:api:messages:2.0:BulkRequest']], 'invalidSyntax'],
    'empty Operations' => [['Operations' => []], 'invalidSyntax'],
    'failOnErrors zero' => [['failOnErrors' => 0, 'Operations' => [['method' => 'DELETE', 'path' => '/Users/x']]], 'invalidValue'],
    'failOnErrors string' => [['failOnErrors' => '1', 'Operations' => [['method' => 'DELETE', 'path' => '/Users/x']]], 'invalidValue'],
]);

it('accepts the Operations key in any case', function (): void {
    $this->postJson('/scim/v2/Bulk', ['operations' => [
        ['METHOD' => 'post', 'Path' => '/users', 'BulkId' => 'lc', 'Data' => ['userName' => 'lower']],
    ]], $this->scimHeaders)->assertOk()->assertJsonPath('Operations.0.status', '201');
});

it('answers 413 naming the limit when maxOperations is exceeded', function (): void {
    config(['cbox-id.scim.bulk.max_operations' => 2]);

    $this->postJson('/scim/v2/Bulk', ['Operations' => array_fill(0, 3, ['method' => 'DELETE', 'path' => '/Users/x'])], $this->scimHeaders)
        ->assertStatus(413)
        ->assertJsonPath('status', '413')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('detail', 'The number of operations (3) exceeds the maxOperations (2).')
        ->assertHeader('Content-Type', 'application/scim+json');
});

it('answers 413 naming the limit when maxPayloadSize is exceeded, before decoding', function (): void {
    config(['cbox-id.scim.bulk.max_payload_size' => 256]);

    $this->postJson('/scim/v2/Bulk', ['Operations' => [
        ['method' => 'POST', 'path' => '/Users', 'bulkId' => 'big', 'data' => ['userName' => str_repeat('x', 400)]],
    ]], $this->scimHeaders)
        ->assertStatus(413)
        ->assertJsonPath('detail', 'The size of the bulk operation exceeds the maxPayloadSize (256).');

    expect(DirectoryUser::query()->count())->toBe(0);
});

it('requires the directory bearer token and stays inside its directory', function (): void {
    $this->postJson('/scim/v2/Bulk', ['Operations' => [['method' => 'DELETE', 'path' => '/Users/x']]])
        ->assertStatus(401);

    $otherHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
    $foreign = (string) $this->postJson('/scim/v2/Users', ['userName' => 'foreign'], $otherHeaders)->json('id');

    bulk($this, [
        ['method' => 'PATCH', 'path' => '/Users/'.$foreign, 'data' => ['Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]]]],
        ['method' => 'DELETE', 'path' => '/Users/'.$foreign],
    ])->assertOk()
        ->assertJsonPath('Operations.0.status', '404')
        ->assertJsonPath('Operations.1.status', '404');

    $this->getJson('/scim/v2/Users/'.$foreign, $otherHeaders)->assertJsonPath('active', true);
});
