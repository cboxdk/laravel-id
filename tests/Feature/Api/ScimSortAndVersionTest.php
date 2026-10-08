<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Cbox\Id\Api\Contracts\ScimUserResources;
use Cbox\Id\Directory\Contracts\DirectoryUsers;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Directory\ValueObjects\DirectoryPage;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

/**
 * Sorting (RFC 7644 §3.4.2.3) and resource versioning with ETags (§3.14).
 */
beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
});

/**
 * @param  array<string, mixed>  $body
 */
function versionedUser(object $test, array $body): string
{
    return (string) $test->postJson('/scim/v2/Users', $body, $test->scimHeaders)->assertCreated()->json('id');
}

/**
 * @return list<string>
 */
function sortedUserNames(object $test, string $query): array
{
    return array_map(
        static fn (array $resource): string => $resource['userName'],
        $test->getJson('/scim/v2/Users?'.$query, $test->scimHeaders)->assertOk()->json('Resources'),
    );
}

// ---------------------------------------------------------------------------
// Sorting
// ---------------------------------------------------------------------------

it('sorts users ascending by default and descending on request', function (): void {
    versionedUser($this, ['userName' => 'Bravo', 'name' => ['givenName' => 'Zed']]);
    versionedUser($this, ['userName' => 'alpha', 'name' => ['givenName' => 'Yan']]);
    versionedUser($this, ['userName' => 'Charlie']);

    // userName is caseExact:false, so "alpha" sorts before "Bravo" whatever the collation.
    expect(sortedUserNames($this, 'sortBy=userName'))->toBe(['alpha', 'Bravo', 'Charlie'])
        ->and(sortedUserNames($this, 'sortBy=userName&sortOrder=descending'))->toBe(['Charlie', 'Bravo', 'alpha'])
        ->and(sortedUserNames($this, 'sortBy=USERNAME&sortOrder=Descending'))->toBe(['Charlie', 'Bravo', 'alpha'])
        ->and(sortedUserNames($this, 'sortBy=urn:ietf:params:scim:schemas:core:2.0:User:userName&sortOrder=ascending'))->toBe(['alpha', 'Bravo', 'Charlie']);
});

it('puts resources with no value last ascending and first descending', function (): void {
    versionedUser($this, ['userName' => 'Bravo', 'name' => ['givenName' => 'Zed']]);
    versionedUser($this, ['userName' => 'alpha', 'name' => ['givenName' => 'Yan']]);
    versionedUser($this, ['userName' => 'Charlie']);

    expect(sortedUserNames($this, 'sortBy=name.givenName'))->toBe(['alpha', 'Bravo', 'Charlie'])
        ->and(sortedUserNames($this, 'sortBy=name.givenName&sortOrder=descending'))->toBe(['Charlie', 'Bravo', 'alpha']);
});

it('sorts by a date and pages a sorted result stably', function (): void {
    $ids = [];
    foreach (['u1', 'u2', 'u3', 'u4'] as $name) {
        $ids[$name] = versionedUser($this, ['userName' => $name]);
    }

    // Two share a timestamp: the secondary order by id keeps every page consistent.
    DirectoryUser::query()->whereKey($ids['u3'])->toBase()->update(['created_at' => '2026-01-01 00:00:00']);
    DirectoryUser::query()->whereKey($ids['u1'])->toBase()->update(['created_at' => '2026-01-01 00:00:00']);
    DirectoryUser::query()->whereKey($ids['u4'])->toBase()->update(['created_at' => '2025-01-01 00:00:00']);
    DirectoryUser::query()->whereKey($ids['u2'])->toBase()->update(['created_at' => '2027-01-01 00:00:00']);

    $page1 = sortedUserNames($this, 'sortBy=meta.created&count=2&startIndex=1');
    $page2 = sortedUserNames($this, 'sortBy=meta.created&count=2&startIndex=3');

    expect($page1[0])->toBe('u4')
        ->and($page2[1])->toBe('u2')
        ->and(array_merge($page1, $page2))->toHaveCount(4)
        ->and(array_unique(array_merge($page1, $page2)))->toHaveCount(4);
});

it('sorts groups by displayName', function (): void {
    foreach (['beta', 'Alpha', 'gamma'] as $name) {
        $this->postJson('/scim/v2/Groups', ['displayName' => $name], $this->scimHeaders)->assertCreated();
    }

    $names = fn (string $query): array => array_map(
        static fn (array $group): string => $group['displayName'],
        $this->getJson('/scim/v2/Groups?'.$query, $this->scimHeaders)->assertOk()->json('Resources'),
    );

    expect($names('sortBy=displayName'))->toBe(['Alpha', 'beta', 'gamma'])
        ->and($names('sortBy=displayName&sortOrder=descending'))->toBe(['gamma', 'beta', 'Alpha']);
});

it('combines a filter with a sort', function (): void {
    foreach (['carol', 'ann', 'bob'] as $name) {
        versionedUser($this, ['userName' => $name.'@corp.com']);
    }

    expect(sortedUserNames($this, 'filter='.rawurlencode('userName ne "bob@corp.com"').'&sortBy=userName&sortOrder=descending'))
        ->toBe(['carol@corp.com', 'ann@corp.com']);
});

/**
 * RFC 7644 §3.4.2.3 says the server SHALL order by the attribute, and says nothing about
 * one it cannot. Silently ordering by something else would hand a client paging through
 * "sorted" results an order it did not ask for, with no way to tell — so it is refused.
 */
it('refuses an attribute it cannot sort by, and an unknown sortOrder', function (string $query): void {
    $this->getJson('/scim/v2/Users?'.$query, $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidValue');
})->with([
    'not stored' => ['sortBy=title'],
    'a convention, not a value' => ['sortBy=emails.type'],
    'a value filter' => ['sortBy='.rawurlencode('emails[type eq "work"]')],
    'unparsable' => ['sortBy='.rawurlencode('user name')],
    'unknown direction' => ['sortBy=userName&sortOrder=sideways'],
]);

it('refuses to sort groups by membership', function (): void {
    $this->getJson('/scim/v2/Groups?sortBy=members', $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidValue');
});

it('refuses sortBy when the bound store cannot sort, instead of ignoring it', function (): void {
    $store = new class implements DirectoryUsers
    {
        public function list(Directory $directory, string $filter, ?int $startIndex, ?int $count): DirectoryPage
        {
            return new DirectoryPage(new Collection, 0, 1);
        }

        public function find(Directory $directory, string $id): ?DirectoryUser
        {
            return null;
        }
    };

    $this->app->instance(DirectoryUsers::class, $store);
    $this->app->forgetInstance(ScimUserResources::class);

    $this->getJson('/scim/v2/Users?sortBy=userName', $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidValue');

    // Without sortBy, the host's store answers as it always did.
    $this->getJson('/scim/v2/Users', $this->scimHeaders)->assertOk()->assertJsonPath('totalResults', 0);
});

// ---------------------------------------------------------------------------
// ETags
// ---------------------------------------------------------------------------

it('carries meta.version and the ETag header on every single-resource response', function (): void {
    $created = $this->postJson('/scim/v2/Users', ['userName' => 'dana'], $this->scimHeaders)->assertCreated();
    $version = $created->json('meta.version');

    expect($version)->toMatch('/^W\/"[0-9a-f]{20}"$/');
    $created->assertHeader('ETag', $version);

    $this->getJson('/scim/v2/Users/'.$created->json('id'), $this->scimHeaders)
        ->assertOk()
        ->assertHeader('ETag', $version)
        ->assertJsonPath('meta.version', $version);

    // Listings carry the version in each resource.
    $this->getJson('/scim/v2/Users', $this->scimHeaders)->assertJsonPath('Resources.0.meta.version', $version);
});

it('changes the version on every write, even within the same second', function (): void {
    CarbonImmutable::setTestNow('2026-10-20 12:00:00');
    Carbon::setTestNow('2026-10-20 12:00:00');

    $id = versionedUser($this, ['userName' => 'dana']);
    $versions = [$this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->json('meta.version')];

    foreach (['Dana A', 'Dana B'] as $name) {
        $versions[] = $this->patchJson('/scim/v2/Users/'.$id, [
            'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => $name]],
        ], $this->scimHeaders)->assertOk()->json('meta.version');
    }

    expect(array_unique($versions))->toHaveCount(3);

    // A write that changes nothing is the same representation, and keeps its tag.
    $again = $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Dana B']],
    ], $this->scimHeaders)->json('meta.version');

    expect($again)->toBe($versions[2]);

    Carbon::setTestNow();
    CarbonImmutable::setTestNow();
});

it('answers a conditional GET with 304 and no body', function (): void {
    $id = versionedUser($this, ['userName' => 'dana']);
    $version = $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->json('meta.version');

    $response = $this->get('/scim/v2/Users/'.$id, $this->scimHeaders + ['If-None-Match' => $version]);

    $response->assertStatus(304)->assertHeader('ETag', $version);
    expect($response->getContent())->toBe('');

    // A list of tags, `*`, and the strong spelling of the same tag all match weakly.
    $this->get('/scim/v2/Users/'.$id, $this->scimHeaders + ['If-None-Match' => 'W/"nope", '.$version])->assertStatus(304);
    $this->get('/scim/v2/Users/'.$id, $this->scimHeaders + ['If-None-Match' => '*'])->assertStatus(304);
    $this->get('/scim/v2/Users/'.$id, $this->scimHeaders + ['If-None-Match' => substr($version, 2)])->assertStatus(304);

    // A stale tag gets the resource.
    $this->get('/scim/v2/Users/'.$id, $this->scimHeaders + ['If-None-Match' => 'W/"stale"'])->assertOk()->assertJsonPath('id', $id);
});

it('refuses a write whose If-Match is stale with 412, and applies nothing', function (string $method): void {
    $id = versionedUser($this, ['userName' => 'dana', 'displayName' => 'Dana']);
    $stale = 'W/"stale"';

    $body = match ($method) {
        'PUT' => ['userName' => 'dana', 'displayName' => 'Overwritten'],
        'PATCH' => ['Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Overwritten']]],
        default => [],
    };

    $this->json($method, '/scim/v2/Users/'.$id, $body, $this->scimHeaders + ['If-Match' => $stale])
        ->assertStatus(412)
        ->assertJsonPath('status', '412')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('displayName', 'Dana')
        ->assertJsonPath('active', true);
})->with(['PUT', 'PATCH', 'DELETE']);

it('applies a write whose If-Match is current, a list containing it, or *', function (): void {
    $id = versionedUser($this, ['userName' => 'dana']);
    $version = $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->json('meta.version');

    $next = $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'One']],
    ], $this->scimHeaders + ['If-Match' => $version])->assertOk()->json('meta.version');

    // The tag just used is now stale: the lost update ETags exist to catch.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Lost']],
    ], $this->scimHeaders + ['If-Match' => $version])->assertStatus(412);

    $this->putJson('/scim/v2/Users/'.$id, ['userName' => 'dana', 'displayName' => 'Two'], $this->scimHeaders + ['If-Match' => 'W/"other", '.$next])
        ->assertOk()
        ->assertJsonPath('displayName', 'Two');

    $this->deleteJson('/scim/v2/Users/'.$id, [], $this->scimHeaders + ['If-Match' => '*'])->assertNoContent();
});

it('versions groups, and moves the version when only membership changes', function (): void {
    $alice = versionedUser($this, ['userName' => 'alice']);
    $group = $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $this->scimHeaders)->assertCreated();
    $id = $group->json('id');
    $v1 = $group->json('meta.version');

    $group->assertHeader('ETag', $v1);

    $v2 = $this->patchJson('/scim/v2/Groups/'.$id, [
        'Operations' => [['op' => 'add', 'path' => 'members', 'value' => [['value' => $alice]]]],
    ], $this->scimHeaders + ['If-Match' => $v1])->assertOk()->json('meta.version');

    expect($v2)->not->toBe($v1);

    // Re-adding the same member changes nothing, and keeps the tag.
    $v3 = $this->patchJson('/scim/v2/Groups/'.$id, [
        'Operations' => [['op' => 'add', 'path' => 'members', 'value' => [['value' => $alice]]]],
    ], $this->scimHeaders)->json('meta.version');

    expect($v3)->toBe($v2);

    $this->get('/scim/v2/Groups/'.$id, $this->scimHeaders + ['If-None-Match' => $v2])->assertStatus(304);

    $this->putJson('/scim/v2/Groups/'.$id, ['displayName' => 'Engineering', 'members' => []], $this->scimHeaders + ['If-Match' => $v1])
        ->assertStatus(412);

    $this->deleteJson('/scim/v2/Groups/'.$id, [], $this->scimHeaders + ['If-Match' => $v2])->assertNoContent();
});

it('answers 404, not 412, for an unknown id with If-Match', function (): void {
    $this->patchJson('/scim/v2/Users/nope', ['Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]]], $this->scimHeaders + ['If-Match' => '*'])
        ->assertNotFound();
});

it('advertises sort, etag and bulk in ServiceProviderConfig', function (): void {
    config(['cbox-id.scim.bulk.max_operations' => 50, 'cbox-id.scim.bulk.max_payload_size' => 65536]);

    $this->getJson('/scim/v2/ServiceProviderConfig', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('patch.supported', true)
        ->assertJsonPath('filter.supported', true)
        ->assertJsonPath('filter.maxResults', 200)
        ->assertJsonPath('sort.supported', true)
        ->assertJsonPath('etag.supported', true)
        ->assertJsonPath('bulk.supported', true)
        ->assertJsonPath('bulk.maxOperations', 50)
        ->assertJsonPath('bulk.maxPayloadSize', 65536)
        ->assertJsonPath('changePassword.supported', false);
});
