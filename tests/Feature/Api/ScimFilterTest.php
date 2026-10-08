<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/**
 * The full RFC 7644 §3.4.2.2 filter grammar, end to end: parsed, translated to SQL over
 * the attributes the directory stores, and answered — or refused with `invalidFilter`
 * when it names something the store does not hold.
 */
beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];

    $this->dana = filterSeedUser($this, [
        'userName' => 'dana.rivera@corp.com', 'externalId' => 'ext-dana',
        'name' => ['givenName' => 'Dana', 'familyName' => 'Rivera'],
        'emails' => [['value' => 'dana.rivera@corp.com', 'type' => 'work', 'primary' => true]],
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' => ['department' => 'Engineering', 'employeeNumber' => '1042', 'manager' => ['value' => 'mgr-1']],
    ]);
    $this->sam = filterSeedUser($this, [
        'userName' => 'sam.ito@corp.com', 'externalId' => 'ext-sam',
        'name' => ['givenName' => 'Sam', 'familyName' => "O'Malley"],
        'emails' => [['value' => 'sam@example.org', 'primary' => true]],
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User' => ['department' => 'Sales'],
    ]);
    $this->lee = filterSeedUser($this, [
        'userName' => 'lee_x@corp.com', 'externalId' => 'ext-lee', 'active' => false,
    ]);
});

/**
 * @param  array<string, mixed>  $body
 */
function filterSeedUser(object $test, array $body): string
{
    return (string) $test->postJson('/scim/v2/Users', $body, $test->scimHeaders)->assertCreated()->json('id');
}

/**
 * @return list<string>
 */
function filterUserNames(object $test, string $filter): array
{
    $response = $test->getJson('/scim/v2/Users?filter='.rawurlencode($filter), $test->scimHeaders)->assertOk();

    $names = array_map(static fn (array $resource): string => $resource['userName'], $response->json('Resources'));
    sort($names);

    expect($response->json('totalResults'))->toBe(count($names));

    return $names;
}

it('answers filters over every stored User attribute', function (string $filter, array $expected): void {
    expect(filterUserNames($this, $filter))->toBe($expected);
})->with([
    'userName, folded' => ['userName eq "DANA.RIVERA@corp.com"', ['dana.rivera@corp.com']],
    'URN-qualified userName' => ['urn:ietf:params:scim:schemas:core:2.0:User:userName sw "sam"', ['sam.ito@corp.com']],
    'attribute name in any case' => ['USERNAME eq "sam.ito@corp.com"', ['sam.ito@corp.com']],
    'externalId' => ['externalId eq "ext-lee"', ['lee_x@corp.com']],
    'externalId is case-exact' => ['externalId eq "EXT-LEE"', []],
    'active' => ['active eq false', ['lee_x@corp.com']],
    'displayName from the name parts' => ['displayName eq "dana rivera"', ['dana.rivera@corp.com']],
    'name.givenName' => ['name.givenName sw "s"', ['sam.ito@corp.com']],
    'name.familyName with an apostrophe' => ['name.familyName co "O\'Malley"', ['sam.ito@corp.com']],
    'name.familyName with a JSON escape' => ['name.familyName eq "o\\u0027malley"', ['sam.ito@corp.com']],
    'emails' => ['emails co "example.org"', ['sam.ito@corp.com']],
    'emails.value' => ['emails.value ew "@corp.com"', ['dana.rivera@corp.com']],
    'enterprise, qualified' => ['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "engineering"', ['dana.rivera@corp.com']],
    'enterprise, unqualified' => ['department eq "Sales"', ['sam.ito@corp.com']],
    'manager, as Entra checks it' => ['manager eq "mgr-1"', ['dana.rivera@corp.com']],
    'manager.value' => ['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value eq "mgr-1"', ['dana.rivera@corp.com']],
    'employeeNumber as a number' => ['employeeNumber eq 1042', ['dana.rivera@corp.com']],
    'presence' => ['department pr', ['dana.rivera@corp.com', 'sam.ito@corp.com']],
    'eq null' => ['department eq null', ['lee_x@corp.com']],
    'ne includes the absent' => ['department ne "Sales"', ['dana.rivera@corp.com', 'lee_x@corp.com']],
    'string ordering' => ['userName gt "lee"', ['lee_x@corp.com', 'sam.ito@corp.com']],
]);

it('evaluates not, grouping and precedence over real rows', function (string $filter, array $expected): void {
    expect(filterUserNames($this, $filter))->toBe($expected);
})->with([
    'not' => ['not (userName sw "dana")', ['lee_x@corp.com', 'sam.ito@corp.com']],
    // `not` over an attribute some rows lack must still include them: the rows with no
    // department are "not Sales". SQL's three-valued logic would silently drop them.
    'not over an absent attribute' => ['not (department eq "Sales")', ['dana.rivera@corp.com', 'lee_x@corp.com']],
    'and over or' => ['active eq true and userName sw "dana" or userName sw "lee"', ['dana.rivera@corp.com', 'lee_x@corp.com']],
    'grouped or under and' => ['active eq true and (userName sw "dana" or userName sw "lee")', ['dana.rivera@corp.com']],
    // lee has no email at all, so neither `co` holds and the `not` does.
    'the RFC not example' => ['userName ne "x" and not (emails co "example.org" or emails.value co "example.net")', ['dana.rivera@corp.com', 'lee_x@corp.com']],
]);

it('evaluates value filters on the stored email', function (string $filter, array $expected): void {
    expect(filterUserNames($this, $filter))->toBe($expected);
})->with([
    'work and value' => ['emails[type eq "work" and value co "rivera"]', ['dana.rivera@corp.com']],
    'primary' => ['emails[primary eq true]', ['dana.rivera@corp.com', 'sam.ito@corp.com']],
    'home names nothing stored' => ['emails[type eq "home"]', []],
    'the Entra uniqueness form' => ['emails[type eq "work"].value eq "SAM@example.org"', ['sam.ito@corp.com']],
    'emails.type' => ['emails.type eq "work"', ['dana.rivera@corp.com', 'sam.ito@corp.com']],
    'emails.type ne' => ['emails.type ne "work"', ['lee_x@corp.com']],
]);

it('treats LIKE metacharacters in substring filters literally', function (): void {
    expect(filterUserNames($this, 'userName co "_x"'))->toBe(['lee_x@corp.com'])
        ->and(filterUserNames($this, 'userName co "e_x"'))->toBe(['lee_x@corp.com'])
        ->and(filterUserNames($this, 'userName co "%"'))->toBe([])
        ->and(filterUserNames($this, 'userName sw "!"'))->toBe([]);
});

it('compares meta dates chronologically', function (): void {
    DirectoryUser::query()->whereKey($this->sam)->toBase()->update(['updated_at' => '2026-01-01 00:00:00', 'created_at' => '2025-06-01 00:00:00']);

    expect(filterUserNames($this, 'meta.lastModified lt "2026-02-01T00:00:00Z"'))->toBe(['sam.ito@corp.com'])
        ->and(filterUserNames($this, 'meta.lastModified ge "2026-02-01T00:00:00Z"'))->toBe(['dana.rivera@corp.com', 'lee_x@corp.com'])
        ->and(filterUserNames($this, 'meta.created le "2025-06-01T00:00:00Z"'))->toBe(['sam.ito@corp.com'])
        // An offset is a different instant, and is compared as one.
        ->and(filterUserNames($this, 'meta.lastModified lt "2026-01-01T01:00:00+02:00"'))->toBe([]);
});

it('refuses a filter it cannot answer honestly', function (string $filter): void {
    $this->getJson('/scim/v2/Users?filter='.rawurlencode($filter), $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');
})->with([
    'an attribute that is not stored' => ['title eq "VP"'],
    'a tolerated-but-discarded attribute' => ['phoneNumbers pr'],
    'an unknown schema' => ['urn:example:custom:User:shoeSize gt 40'],
    'ordering on a boolean' => ['active gt false'],
    'substring on a boolean' => ['active co "tru"'],
    'substring on a date' => ['meta.created co "2026"'],
    'a non-date against a date' => ['meta.lastModified gt "yesterday"'],
    'a non-boolean against a boolean' => ['active eq "fasle"'],
    'a value filter on a simple attribute' => ['userName[value eq "x"]'],
    'a sub-attribute nothing stores' => ['emails[display eq "x"]'],
    'syntax error' => ['userName eq'],
    'unbalanced parenthesis' => ['(userName eq "x"'],
]);

it('names the problem in the error detail', function (): void {
    $this->getJson('/scim/v2/Users?filter='.rawurlencode('title eq "VP"'), $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('detail', 'The attribute [title] cannot be filtered on.');

    $detail = $this->getJson('/scim/v2/Users?filter='.rawurlencode('userName eq "a" and'), $this->scimHeaders)
        ->assertStatus(400)
        ->json('detail');

    expect($detail)->toContain('position');
});

it('refuses a hostile filter before it reaches the database', function (): void {
    $wide = implode(' or ', array_fill(0, 100, 'userName eq "x"'));
    $deep = str_repeat('(', 40).'userName eq "x"'.str_repeat(')', 40);

    DB::enableQueryLog();

    foreach ([$wide, $deep, 'userName eq "'.str_repeat('a', 5000).'"'] as $filter) {
        $this->getJson('/scim/v2/Users?filter='.rawurlencode($filter), $this->scimHeaders)
            ->assertStatus(400)
            ->assertJsonPath('scimType', 'invalidFilter');
    }

    $touched = array_filter(DB::getQueryLog(), static fn (array $query): bool => str_contains($query['query'], 'directory_users'));

    expect($touched)->toBe([]);
});

it('keeps an or inside the directory scope', function (): void {
    $other = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
    $this->postJson('/scim/v2/Users', ['userName' => 'outsider@else.com'], $other)->assertCreated();

    expect(filterUserNames($this, 'userName eq "outsider@else.com" or not (userName pr)'))->toBe([]);
});

// ---------------------------------------------------------------------------
// /Groups
// ---------------------------------------------------------------------------

it('filters groups by name, id and membership', function (): void {
    $eng = $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering', 'externalId' => 'g-eng', 'members' => [['value' => $this->dana], ['value' => $this->sam]]], $this->scimHeaders)->json('id');
    $ops = $this->postJson('/scim/v2/Groups', ['displayName' => 'Operations', 'members' => [['value' => $this->sam]]], $this->scimHeaders)->json('id');

    $names = function (string $filter): array {
        $response = $this->getJson('/scim/v2/Groups?filter='.rawurlencode($filter), $this->scimHeaders)->assertOk();
        $names = array_map(static fn (array $group): string => $group['displayName'], $response->json('Resources'));
        sort($names);

        return $names;
    };

    expect($names('displayName eq "engineering"'))->toBe(['Engineering'])
        ->and($names('displayName sw "op"'))->toBe(['Operations'])
        ->and($names('id eq "'.$ops.'"'))->toBe(['Operations'])
        ->and($names('members[value eq "'.$this->dana.'"]'))->toBe(['Engineering'])
        ->and($names('members.value eq "'.$this->sam.'"'))->toBe(['Engineering', 'Operations'])
        ->and($names('members eq "'.$this->sam.'"'))->toBe(['Engineering', 'Operations'])
        ->and($names('members[display eq "SAM.ITO@corp.com"]'))->toBe(['Engineering', 'Operations'])
        ->and($names('not (members.value eq "'.$this->dana.'")'))->toBe(['Operations'])
        // The bracket is one member: no single member is both dana and sam.
        ->and($names('members[value eq "'.$this->dana.'" and value eq "'.$this->sam.'"]'))->toBe([])
        ->and($names('members.value eq "'.$this->dana.'" and members.value eq "'.$this->sam.'"'))->toBe(['Engineering'])
        // Entra's existence check: this group, with this member.
        ->and($names('id eq "'.$eng.'" and members[value eq "'.$this->dana.'"]'))->toBe(['Engineering'])
        ->and($names('members pr'))->toBe(['Engineering', 'Operations']);
});

it('refuses a group filter on an attribute groups do not store', function (): void {
    $this->getJson('/scim/v2/Groups?filter='.rawurlencode('userName eq "x"'), $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter');
});
