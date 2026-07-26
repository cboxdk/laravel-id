<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $org = $this->makeOrganization();
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($org->id)->token];
});

/**
 * @param  array<string, string>  $headers
 * @return list<string>
 */
function scimMembers(object $test, array $headers, int $count): array
{
    $ids = [];

    foreach (range(1, $count) as $i) {
        $ids[] = (string) $test->postJson('/scim/v2/Users', [
            'userName' => 'member'.$i,
            'externalId' => 'idp|'.$i,
            'active' => true,
        ], $headers)->json('id');
    }

    return $ids;
}

/**
 * @param  array<string, string>  $headers
 */
function scimGroup(object $test, array $headers, string $displayName, array $memberIds): string
{
    return (string) $test->postJson('/scim/v2/Groups', [
        'displayName' => $displayName,
        'members' => array_map(static fn (string $id): array => ['value' => $id], $memberIds),
    ], $headers)->json('id');
}

it('omits members from a listing, so a page of large groups is not a memory bomb', function (): void {
    $headers = $this->scimHeaders;
    $members = scimMembers($this, $headers, 3);
    scimGroup($this, $headers, 'Engineering', $members);

    $response = $this->getJson('/scim/v2/Groups', $headers)->assertOk();

    // Omitted, not emitted empty: `members: []` would assert the group HAS no
    // members, which is a different and wrong fact.
    expect($response->json('Resources.0'))->not->toHaveKey('members')
        ->and($response->json('Resources.0.displayName'))->toBe('Engineering')
        ->and($response->json('totalResults'))->toBe(1);
});

it('returns members in a listing when the client asks for them', function (): void {
    $headers = $this->scimHeaders;
    $members = scimMembers($this, $headers, 3);
    scimGroup($this, $headers, 'Engineering', $members);

    $this->getJson('/scim/v2/Groups?attributes=members', $headers)
        ->assertOk()
        ->assertJsonCount(3, 'Resources.0.members');
});

it('accepts a fully qualified attribute name', function (): void {
    $headers = $this->scimHeaders;
    scimGroup($this, $headers, 'Engineering', scimMembers($this, $headers, 2));

    $this->getJson('/scim/v2/Groups?attributes=urn:ietf:params:scim:schemas:core:2.0:Group:members', $headers)
        ->assertOk()
        ->assertJsonCount(2, 'Resources.0.members');
});

it('still returns members when a single group is read', function (): void {
    $headers = $this->scimHeaders;
    $members = scimMembers($this, $headers, 3);
    $groupId = scimGroup($this, $headers, 'Engineering', $members);

    $this->getJson('/scim/v2/Groups/'.$groupId, $headers)
        ->assertOk()
        ->assertJsonCount(3, 'members');
});

it('honours excludedAttributes on a single group', function (): void {
    $headers = $this->scimHeaders;
    $groupId = scimGroup($this, $headers, 'Engineering', scimMembers($this, $headers, 2));

    $response = $this->getJson('/scim/v2/Groups/'.$groupId.'?excludedAttributes=members', $headers)->assertOk();

    expect($response->json())->not->toHaveKey('members')
        ->and($response->json('displayName'))->toBe('Engineering');
});

/**
 * The exclusion must be scoped to the attribute actually NAMED. Excluding something
 * else entirely — Entra sends `excludedAttributes=members`, but plenty of clients
 * exclude other attributes — must leave membership alone, or a client that asked to
 * drop `externalId` is quietly told the group has no members.
 */
it('only suppresses members when members is the attribute excluded', function (string $query, bool $expected): void {
    $headers = $this->scimHeaders;
    $groupId = scimGroup($this, $headers, 'Engineering', scimMembers($this, $headers, 2));

    $response = $this->getJson('/scim/v2/Groups/'.$groupId.'?'.$query, $headers)->assertOk();

    expect(array_key_exists('members', (array) $response->json()))->toBe($expected);
})->with([
    'a different attribute' => ['excludedAttributes=externalId', true],
    'a name that merely contains members' => ['excludedAttributes=membersCount', true],
    'members itself' => ['excludedAttributes=members', false],
    'members among others' => ['excludedAttributes=externalId,members', false],
]);

it('does not read the membership pivot at all for a default listing', function (): void {
    $headers = $this->scimHeaders;
    scimGroup($this, $headers, 'Engineering', scimMembers($this, $headers, 3));

    $membershipQueries = 0;
    DB::listen(function ($query) use (&$membershipQueries): void {
        if (str_contains($query->sql, 'directory_group_user') || str_contains($query->sql, 'directory_users')) {
            $membershipQueries++;
        }
    });

    $this->getJson('/scim/v2/Groups', $headers)->assertOk();

    // The eager load is what turned `?count=200` against several 20k-member groups
    // into hundreds of thousands of hydrated models.
    expect($membershipQueries)->toBe(0);
});
