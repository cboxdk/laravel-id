<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $org = $this->makeOrganization();
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($org->id)->token];
});

/**
 * @param  array<string, string>  $headers
 */
function provision(object $test, array $headers, string $userName, string $externalId, string $email): string
{
    return (string) $test->postJson('/scim/v2/Users', [
        'userName' => $userName,
        'externalId' => $externalId,
        'emails' => [['value' => $email, 'primary' => true]],
        'active' => true,
    ], $headers)->json('id');
}

it('lists users with a ListResponse envelope', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');
    provision($this, $headers, 'sam', 'okta|2', 'sam@corp.com');

    $this->getJson('/scim/v2/Users', $headers)
        ->assertOk()
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:ListResponse')
        ->assertJsonPath('totalResults', 2)
        ->assertJsonPath('itemsPerPage', 2)
        ->assertJsonCount(2, 'Resources');
});

it('filters users by userName eq (the Okta/Entra existence check)', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');
    provision($this, $headers, 'sam', 'okta|2', 'sam@corp.com');

    $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "sam"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.userName', 'sam');
});

it('treats LIKE metacharacters in a co filter as literals, not wildcards', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');
    provision($this, $headers, 'sam', 'okta|2', 'sam@corp.com');

    // `_` is a SQL LIKE single-char wildcard. Unescaped, `d_na` would match
    // "dana"; escaped, it is a literal underscore and matches nothing.
    $this->getJson('/scim/v2/Users?filter='.urlencode('userName co "d_na"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);

    // `%` unescaped would match every user; escaped it matches only a literal %.
    $this->getJson('/scim/v2/Users?filter='.urlencode('userName co "%"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);

    // A genuine substring still matches.
    $this->getJson('/scim/v2/Users?filter='.urlencode('userName co "an"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.userName', 'dana');
});

it('filters users by externalId eq', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');

    $this->getJson('/scim/v2/Users?filter='.urlencode('externalId eq "okta|1"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.externalId', 'okta|1');

    $this->getJson('/scim/v2/Users?filter='.urlencode('externalId eq "missing"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);
});

it('filters users by a compound `and` (Entra userName + active)', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');
    provision($this, $headers, 'sam', 'okta|2', 'sam@corp.com');

    // Both clauses hold for sam → 1 match.
    $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "sam" and active eq true'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.userName', 'sam');

    // The second clause excludes everyone → 0, proving both are applied (not just the first).
    $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "sam" and active eq false'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);
});

it('filters users by a compound `or` grouped inside the directory scope', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');
    provision($this, $headers, 'sam', 'okta|2', 'sam@corp.com');
    provision($this, $headers, 'lee', 'okta|3', 'lee@corp.com');

    $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "dana" or userName eq "lee"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 2);
});

it('refuses a filter that mixes `and` with `or` (ambiguous precedence)', function (): void {
    $headers = $this->scimHeaders;

    $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "a" and active eq true or userName eq "b"'), $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter');
});

it('rejects an unsupported filter with invalidFilter', function (): void {
    $headers = $this->scimHeaders;

    $this->getJson('/scim/v2/Users?filter='.urlencode('emails[type eq "work"] pr and userName sw "x"'), $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter');
});

it('serves SCIM responses as application/scim+json (RFC 7644 §3.1)', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');

    $this->getJson('/scim/v2/Users', $headers)
        ->assertOk()
        ->assertHeader('Content-Type', 'application/scim+json');

    // Error bodies carry the SCIM media type too.
    $this->getJson('/scim/v2/Users?filter='.urlencode('bogus'), $headers)
        ->assertStatus(400)
        ->assertHeader('Content-Type', 'application/scim+json');
});

it('paginates with startIndex and count', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'a', 'x|1', 'a@corp.com');
    provision($this, $headers, 'b', 'x|2', 'b@corp.com');
    provision($this, $headers, 'c', 'x|3', 'c@corp.com');

    $this->getJson('/scim/v2/Users?startIndex=2&count=1', $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 3)
        ->assertJsonPath('startIndex', 2)
        ->assertJsonCount(1, 'Resources');
});

it('replaces a user with PUT', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');

    $this->putJson('/scim/v2/Users/'.$id, [
        'userName' => 'dana.reeves',
        'externalId' => 'okta|1',
        'displayName' => 'Dana Reeves',
        'emails' => [['value' => 'dana.reeves@corp.com', 'primary' => true]],
        'active' => true,
    ], $headers)
        ->assertOk()
        ->assertJsonPath('userName', 'dana.reeves')
        ->assertJsonPath('displayName', 'Dana Reeves')
        ->assertJsonPath('emails.0.value', 'dana.reeves@corp.com');
});

it('patches core attributes (displayName + userName) via path operations', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'replace', 'path' => 'displayName', 'value' => 'Dana R.'],
            ['op' => 'replace', 'path' => 'userName', 'value' => 'dana.r'],
        ],
    ], $headers)
        ->assertOk()
        ->assertJsonPath('userName', 'dana.r')
        ->assertJsonPath('displayName', 'Dana R.')
        ->assertJsonPath('active', true);
});

it('applies a remove operation by clearing the targeted attribute', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana', 'okta|1', 'dana@corp.com');

    // Set a display name, then remove it — the remove must actually take effect,
    // not be silently ignored.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Dana R.']],
    ], $headers)->assertOk()->assertJsonPath('displayName', 'Dana R.');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'remove', 'path' => 'displayName']],
    ], $headers)
        ->assertOk()
        ->assertJsonPath('displayName', null)
        ->assertJsonPath('userName', 'dana'); // required attribute untouched
});

it('refuses a PUT whose body externalId names a different resource (no IDOR)', function (): void {
    $headers = $this->scimHeaders;
    $idA = provision($this, $headers, 'anna', 'okta|A', 'anna@corp.com');
    provision($this, $headers, 'bob', 'okta|B', 'bob@corp.com');

    // PUT /Users/{A} with the body claiming externalId B must be refused, not silently
    // mutate/create B while leaving A intact.
    $this->putJson("/scim/v2/Users/{$idA}", [
        'userName' => 'anna', 'externalId' => 'okta|B',
        'emails' => [['value' => 'anna@corp.com', 'primary' => true]], 'active' => true,
    ], $headers)->assertStatus(400)->assertJsonPath('scimType', 'mutability');

    // A still resolves by its own externalId, unchanged.
    $this->getJson('/scim/v2/Users?filter='.urlencode('externalId eq "okta|A"'), $headers)
        ->assertOk()->assertJsonPath('totalResults', 1);
});

it('refuses a create whose userName is already taken in the directory (409 uniqueness)', function (): void {
    $headers = $this->scimHeaders;
    provision($this, $headers, 'anna', 'okta|A', 'anna@corp.com');

    // Different externalId + email, same userName → uniqueness=server must reject.
    $this->postJson('/scim/v2/Users', [
        'userName' => 'anna', 'externalId' => 'okta|B',
        'emails' => [['value' => 'anna.two@corp.com', 'primary' => true]], 'active' => true,
    ], $headers)->assertStatus(409)->assertJsonPath('scimType', 'uniqueness');
});

it('refuses a create with no userName (400 invalidValue)', function (): void {
    $this->postJson('/scim/v2/Users', [
        'externalId' => 'okta|X', 'emails' => [['value' => 'x@corp.com', 'primary' => true]],
    ], $this->scimHeaders)->assertStatus(400)->assertJsonPath('scimType', 'invalidValue');
});

it('binds a PUT to the URL target even when the body omits externalId', function (): void {
    $headers = $this->scimHeaders;
    $idA = provision($this, $headers, 'anna@corp.com', 'okta|A', 'anna@corp.com');

    // PUT /Users/{A} with NO externalId and a different userName. The mapper falls
    // back externalId=userName, so without pinning this would re-key the write to a
    // NEW row ("bob@corp.com") and leave A untouched — a wrong-user/confused-deputy
    // write. The target must stay bound to the URL.
    $this->putJson("/scim/v2/Users/{$idA}", [
        'userName' => 'bob@corp.com',
        'emails' => [['value' => 'bob@corp.com', 'primary' => true]], 'active' => true,
    ], $headers)->assertOk()->assertJsonPath('id', $idA);

    // A was updated in place: its externalId is unchanged, its userName replaced.
    expect(DirectoryUser::query()->count())->toBe(1);
    $this->getJson('/scim/v2/Users/'.$idA, $headers)
        ->assertOk()
        ->assertJsonPath('externalId', 'okta|A')
        ->assertJsonPath('userName', 'bob@corp.com');

    // No phantom row keyed on the body userName was created.
    $this->getJson('/scim/v2/Users?filter='.urlencode('externalId eq "bob@corp.com"'), $headers)
        ->assertOk()->assertJsonPath('totalResults', 0);
});

/**
 * Recorded-shape tests for the two IdPs that actually matter. The suite previously
 * exercised PATCH only through paths WE chose, so it proved the mapper agreed with
 * itself — the one thing a spec misreading cannot fail.
 */
it('applies an Okta-shaped name PATCH (givenName/familyName)', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana@corp.com', 'okta|1', 'dana@corp.com');

    // Okta's default profile sends the name PARTS — never name.formatted, never
    // displayName. These used to fall through to a silent no-op, so every Okta user
    // kept their email address as their display name, permanently and invisibly.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'replace', 'path' => 'name.givenName', 'value' => 'Dana'],
            ['op' => 'replace', 'path' => 'name.familyName', 'value' => 'Rivera'],
        ],
    ], $headers)
        ->assertOk()
        ->assertJsonPath('displayName', 'Dana Rivera');
});

it('applies an Entra-shaped email PATCH whatever the value filter looks like', function (): void {
    $headers = $this->scimHeaders;

    // Entra sends a value-filter path. Only ONE exact spelling used to be recognised;
    // any variation in quoting, casing or type fell through to a silent no-op.
    $variants = [
        'emails[type eq "work"].value',
        'emails[type EQ "work"].value',
        "emails[type eq 'work'].value",
        'emails[primary eq true].value',
    ];

    foreach ($variants as $i => $path) {
        $id = provision($this, $headers, "user{$i}", "entra|{$i}", "old{$i}@corp.com");

        $this->patchJson('/scim/v2/Users/'.$id, [
            'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations' => [['op' => 'replace', 'path' => $path, 'value' => "new{$i}@corp.com"]],
        ], $headers)
            ->assertOk()
            ->assertJsonPath('emails.0.value', "new{$i}@corp.com");
    }
});

it('refuses an unmapped PATCH path instead of reporting a write it did not make', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana', 'okta|9', 'dana@corp.com');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        // NOT nickName: that is a schema-defined attribute this server simply does not
        // store, so tolerating it is correct. invalidPath is for a path we cannot
        // interpret at all.
        'Operations' => [['op' => 'replace', 'path' => 'notAScimAttribute', 'value' => 'x']],
    ], $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidPath')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');
});

/**
 * The invalidPath fix traded a silent no-op for a HARD FAILURE on the operations that
 * matter. applyPatch throws mid-loop, so one unmapped attribute 400s the whole request —
 * and Entra's default mapping ships phoneNumbers alongside `active`. A deprovision was
 * therefore rejected outright and the user was never deactivated.
 */
it('deactivates a user even when the push carries attributes we do not store', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'leaver@corp.com', 'entra|9', 'leaver@corp.com');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'replace', 'path' => 'active', 'value' => false],
            ['op' => 'replace', 'path' => 'phoneNumbers[type eq "mobile"].value', 'value' => '+45 12 34 56 78'],
            ['op' => 'replace', 'path' => 'title', 'value' => 'Former VP'],
        ],
    ], $headers)
        ->assertOk()
        // The operation that MATTERS must have landed.
        ->assertJsonPath('active', false);
});

it('still refuses a path it cannot interpret at all', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana2', 'okta|11', 'dana2@corp.com');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'notAScimAttribute', 'value' => 'x']],
    ], $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidPath');
});

/**
 * A single-part name PATCH must MERGE with the stored other part. build() previously
 * persisted only the composed displayName, so composing from the patch alone silently
 * dropped whichever part was not sent.
 */
it('keeps the other name part when only one is patched', function (): void {
    $headers = $this->scimHeaders;
    $id = provision($this, $headers, 'dana3@corp.com', 'okta|21', 'dana3@corp.com');

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [
            ['op' => 'replace', 'path' => 'name.givenName', 'value' => 'Dana'],
            ['op' => 'replace', 'path' => 'name.familyName', 'value' => 'Rivera'],
        ],
    ], $headers)->assertOk()->assertJsonPath('displayName', 'Dana Rivera');

    // A surname change alone must not erase the given name.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'name.familyName', 'value' => 'Okonkwo']],
    ], $headers)->assertOk()->assertJsonPath('displayName', 'Dana Okonkwo');
});
