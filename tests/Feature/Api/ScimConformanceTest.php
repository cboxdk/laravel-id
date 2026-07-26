<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Cbox\Id\Api\Http\Controllers\Scim\UserController;
use Cbox\Id\Directory\Models\DirectoryUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Http\Request;

uses(RefreshDatabase::class);

/**
 * Conformance tests for the failure mode that matters most on this surface: SILENT
 * SUCCESS. In every case below the server used to answer 2xx for an operation it did
 * not perform — so the calling IdP recorded the write as applied, never retried, and
 * the drift stayed invisible on both sides until somebody audited it by hand.
 */
beforeEach(function (): void {
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($this->makeOrganization()->id)->token];
});

/**
 * @param  array<string, mixed>  $overrides
 */
function createUser(object $test, array $overrides = []): string
{
    return (string) $test->postJson('/scim/v2/Users', array_merge([
        'userName' => 'dana',
        'externalId' => 'okta|1',
        'emails' => [['value' => 'dana@corp.com', 'primary' => true]],
        'active' => true,
    ], $overrides), $test->scimHeaders)->assertStatus(201)->json('id');
}

// ---------------------------------------------------------------------------
// 1. A PATCH whose `Operations` member is missing or misspelled.
// ---------------------------------------------------------------------------

/**
 * RFC 7644 §3.5.2 makes `Operations` mandatory. Degrading anything else to an empty
 * list and answering 200 with the full resource is the worst possible outcome: a
 * connector whose `active:false` body the server could not read is told the
 * deactivation succeeded, so it never retries — and a terminated employee keeps every
 * session they hold.
 */
it('refuses a PATCH whose Operations member is missing, misspelled or empty', function (array $body): void {
    $id = createUser($this);

    $this->patchJson('/scim/v2/Users/'.$id, $body, $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('scimType', 'invalidSyntax');

    // And nothing changed: the refusal must be total, not partial.
    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('active', true);
})->with([
    'absent' => [['schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp']]],
    'misspelled' => [['Operatoins' => [['op' => 'replace', 'path' => 'active', 'value' => false]]]],
    'empty array' => [['Operations' => []]],
    'not an array' => [['Operations' => 'replace active false']],
    'scalar member' => [['Operations' => ['replace']]],
]);

/**
 * RFC 7643 §2.1: "Attribute names are case insensitive." A body spelling `operations`
 * — what a key-normalizing proxy produces, and what several connectors send — is legal
 * SCIM. Refusing it turned the deactivation into a hard 400 on a request the server
 * understood perfectly well, which Entra escalates into a quarantined provisioning job.
 */
it('applies a PATCH whose Operations member differs only in case', function (string $key): void {
    $id = createUser($this);

    $this->patchJson('/scim/v2/Users/'.$id, [
        $key => [['op' => 'replace', 'path' => 'active', 'value' => false]],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('active', false);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('active', false);
})->with(['lower-cased' => 'operations', 'upper-cased' => 'OPERATIONS', 'mixed' => 'oPeRaTiOnS']);

it('refuses a Group PATCH whose Operations member is missing or misspelled', function (): void {
    $groupId = (string) $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $this->scimHeaders)
        ->assertStatus(201)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, [
        'Operatoins' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Hijacked']],
    ], $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidSyntax');

    $this->getJson('/scim/v2/Groups/'.$groupId, $this->scimHeaders)
        ->assertOk()->assertJsonPath('displayName', 'Engineering');
});

/**
 * Case-insensitivity applies to the Group PATCH's `path` and to the keys inside a
 * pathless `value` for exactly the same reason as `Operations`.
 */
it('applies a Group PATCH whose Operations, path and value keys differ in case', function (array $body, string $expected): void {
    $groupId = (string) $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $this->scimHeaders)
        ->assertStatus(201)->json('id');

    $this->patchJson('/scim/v2/Groups/'.$groupId, $body, $this->scimHeaders)->assertOk();

    $this->getJson('/scim/v2/Groups/'.$groupId, $this->scimHeaders)
        ->assertOk()->assertJsonPath('displayName', $expected);
})->with([
    'lower-cased key' => [['operations' => [['op' => 'replace', 'path' => 'displayName', 'value' => 'Platform']]], 'Platform'],
    'lower-cased path' => [['Operations' => [['op' => 'replace', 'path' => 'displayname', 'value' => 'Platform']]], 'Platform'],
    'lower-cased value key' => [['Operations' => [['op' => 'replace', 'value' => ['displayname' => 'Platform']]]], 'Platform'],
]);

// ---------------------------------------------------------------------------
// 2. /Schemas must declare everything the mapper accepts.
// ---------------------------------------------------------------------------

/**
 * An admin running Okta's "Import Schema" gets exactly what this endpoint declares.
 * Declaring four scalars while `name` and `emails` were fully supported on the wire
 * left them with a profile in which email and first/last name were unmappable.
 */
it('declares emails and name on the User schema', function (): void {
    $attributes = collect($this->getJson('/scim/v2/Schemas', $this->scimHeaders)->assertOk()->json('Resources.0.attributes'))
        ->keyBy('name');

    expect($attributes->keys()->all())->toContain('userName', 'externalId', 'name', 'displayName', 'emails', 'active');

    $emails = $attributes->get('emails');
    expect($emails['type'])->toBe('complex')
        ->and($emails['multiValued'])->toBeTrue()
        ->and(collect($emails['subAttributes'])->pluck('name')->all())->toContain('value', 'type', 'primary');

    $name = $attributes->get('name');
    expect($name['type'])->toBe('complex')
        ->and($name['multiValued'])->toBeFalse()
        ->and(collect($name['subAttributes'])->pluck('name')->all())
        ->toContain('formatted', 'givenName', 'familyName');
});

/**
 * RFC 7643 §7 `returned` is a promise, and a schema an IdP cannot trust is worse than
 * one that admits a limitation. `members` was declared `default` while the code
 * implements `request` on a LISTING — and declared `complex` with NO subAttributes,
 * which Okta's schema importer treats as unmappable, so the attribute silently vanished
 * from the imported profile altogether.
 */
it('declares Group.members exactly as the code implements it', function (): void {
    $group = collect($this->getJson('/scim/v2/Schemas', $this->scimHeaders)->assertOk()->json('Resources'))
        ->firstWhere('id', 'urn:ietf:params:scim:schemas:core:2.0:Group');

    $members = collect($group['attributes'])->firstWhere('name', 'members');

    expect($members['returned'])->toBe('request')
        ->and($members['multiValued'])->toBeTrue()
        ->and(collect($members['subAttributes'])->pluck('name')->all())->toContain('value', 'display');
});

/**
 * The mirror of the promise above: an attribute the mapper accepts and then DISCARDS
 * must not be advertised as one you can read back. An admin who maps `middleName`,
 * imports, and finds every value blank has no way to tell a mapping mistake from a
 * server that never stored it.
 */
it('declares the accepted-but-discarded attributes as never returned', function (): void {
    $attributes = collect($this->getJson('/scim/v2/Schemas', $this->scimHeaders)->assertOk()->json('Resources.0.attributes'))
        ->keyBy('name');

    $returned = static fn (array $attribute, string $sub): string => collect($attribute['subAttributes'])
        ->firstWhere('name', $sub)['returned'];

    expect($returned($attributes->get('name'), 'middleName'))->toBe('never')
        ->and($returned($attributes->get('name'), 'honorificPrefix'))->toBe('never')
        ->and($returned($attributes->get('name'), 'honorificSuffix'))->toBe('never')
        ->and($returned($attributes->get('emails'), 'type'))->toBe('never')
        ->and($returned($attributes->get('emails'), 'display'))->toBe('never')
        // The parts the resource DOES carry keep their promise.
        ->and($returned($attributes->get('name'), 'givenName'))->toBe('default')
        ->and($returned($attributes->get('name'), 'familyName'))->toBe('default');
});

// ---------------------------------------------------------------------------
// 3. name.givenName / name.familyName on CREATE and PUT.
// ---------------------------------------------------------------------------

/**
 * Okta's default SCIM profile sends the name PARTS on the create, and never
 * `name.formatted` or `displayName`. Reading only `name.formatted` meant every
 * Okta-provisioned user was created with their email address as their name — and,
 * because the parts were never stored, a later single-part PATCH had nothing to merge
 * with. Neither is recoverable without a hand-written database repair.
 */
it('maps givenName and familyName on CREATE', function (): void {
    $id = createUser($this, [
        'userName' => 'dana@corp.com',
        'name' => ['givenName' => 'Dana', 'familyName' => 'Rivera'],
    ]);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('displayName', 'Dana Rivera')
        ->assertJsonPath('emails.0.value', 'dana@corp.com');

    // The PARTS were persisted, not just the composed name: patching one must merge
    // with the other rather than silently dropping it.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => 'name.familyName', 'value' => 'Okonkwo']],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('displayName', 'Dana Okonkwo');
});

it('keeps the name parts through a PUT', function (): void {
    $id = createUser($this, ['name' => ['givenName' => 'Dana', 'familyName' => 'Rivera']]);

    $this->putJson('/scim/v2/Users/'.$id, [
        'userName' => 'dana',
        'externalId' => 'okta|1',
        'name' => ['givenName' => 'Dana', 'familyName' => 'Rivera'],
        'emails' => [['value' => 'dana@corp.com', 'primary' => true]],
        'active' => true,
    ], $this->scimHeaders)->assertOk()->assertJsonPath('displayName', 'Dana Rivera');

    // A PUT is a full replace, so the parts must be re-read from the body — not
    // dropped, leaving displayName to fall back to the userName forever.
    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => 'name.givenName', 'value' => 'Danielle']],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('displayName', 'Danielle Rivera');
});

/**
 * /Schemas declares `name.givenName`/`name.familyName`, both are persisted, and both are
 * accepted on write — but `toResource()` emitted only `name.formatted`, so they were
 * declared and stored and never handed back. That breaks the resource in two
 * directions at once: an Okta admin who maps `user.firstName ← name.givenName` imports
 * every user with a blank first name, and Entra's read-modify-write PUT reconciliation
 * reads the resource back WITHOUT the parts and pushes that omission straight over the
 * stored values on the next cycle — blanking them.
 */
it('returns the name parts it declares, stores and accepts', function (): void {
    $id = createUser($this, [
        'userName' => 'dana@corp.com',
        'name' => ['givenName' => 'Dana', 'familyName' => 'Rivera'],
    ]);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('name.givenName', 'Dana')
        ->assertJsonPath('name.familyName', 'Rivera')
        ->assertJsonPath('name.formatted', 'Dana Rivera');

    // Entra's reconciliation loop in miniature: read the resource back and PUT it
    // verbatim. The parts must survive the round trip rather than being erased by their
    // own absence.
    $resource = $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->json();

    $this->putJson('/scim/v2/Users/'.$id, $resource, $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('name.givenName', 'Dana')
        ->assertJsonPath('name.familyName', 'Rivera')
        ->assertJsonPath('displayName', 'Dana Rivera');
});

it('prefers the primary address out of a multi-valued emails attribute', function (): void {
    $id = createUser($this, [
        'emails' => [
            ['value' => 'home@personal.test', 'type' => 'home'],
            ['value' => 'dana@corp.com', 'type' => 'work', 'primary' => true],
        ],
    ]);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)
        ->assertOk()->assertJsonPath('emails.0.value', 'dana@corp.com');
});

// ---------------------------------------------------------------------------
// 4. A pathless PATCH must not silently discard `name`.
// ---------------------------------------------------------------------------

/**
 * Entra's default mapping sends the whole resource in a PATHLESS operation. The
 * `name` object fell straight through — 200 OK, nothing changed, on every push,
 * forever — while the identical content under an explicit path 400'd. Both spellings
 * must now apply.
 */
it('applies a name object sent in a pathless PATCH', function (): void {
    $id = createUser($this, ['userName' => 'dana@corp.com']);

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'value' => [
            'name' => ['givenName' => 'Dana', 'familyName' => 'Rivera'],
        ]]],
    ], $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('displayName', 'Dana Rivera');
});

it('applies a name object sent under an explicit name path', function (): void {
    $id = createUser($this, ['userName' => 'dana@corp.com']);

    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => 'name', 'value' => [
            'givenName' => 'Dana', 'familyName' => 'Rivera', 'middleName' => 'Q',
        ]]],
    ], $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('displayName', 'Dana Rivera');
});

/**
 * RFC 7644 §3.5.2.2 is explicit: "If 'path' is unspecified, the operation fails with
 * HTTP status code 400 and a 'scimType' error code of 'noTarget'." A `remove` names
 * what to clear; without a path there is nothing to clear, and skipping it answered 200
 * for an operation the server had not performed.
 */
it('refuses a pathless remove with noTarget instead of silently doing nothing', function (): void {
    $id = createUser($this, ['name' => ['givenName' => 'Dana', 'familyName' => 'Rivera']]);

    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'remove', 'value' => ['displayName' => 'Dana Rivera']]],
    ], $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'noTarget');

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)
        ->assertOk()->assertJsonPath('displayName', 'Dana Rivera');
});

it('still honours a remove that names its target', function (): void {
    $id = createUser($this, ['name' => ['givenName' => 'Dana', 'familyName' => 'Rivera']]);

    $response = $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'remove', 'path' => 'name.givenName']],
    ], $this->scimHeaders)->assertOk();

    expect($response->json())->not->toHaveKey('name.givenName');
});

// ---------------------------------------------------------------------------
// 5. `active` must be parsed strictly, never coerced.
// ---------------------------------------------------------------------------

/**
 * Coercion here is a deprovision: a false `active` deactivates the subject, removes org
 * membership and revokes every session. `Request::boolean()` and FILTER_VALIDATE_BOOLEAN
 * both answer false for anything they do not recognise, so `"active": "fasle"` used to
 * terminate the wrong person and report success.
 */
it('refuses a malformed active on create rather than provisioning a deactivated user', function (mixed $active): void {
    $this->postJson('/scim/v2/Users', [
        'userName' => 'dana', 'externalId' => 'okta|1', 'active' => $active,
    ], $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidValue');

    expect(DirectoryUser::query()->count())->toBe(0);
})->with([
    'misspelled' => 'fasle',
    'yes/no' => 'no',
    'zero' => 0,
    'one' => 1,
    'numeric string' => '1',
    'truthy word' => 'on',
    'near miss' => 'tru',
]);

it('refuses a malformed active on PATCH rather than deactivating', function (array $operation): void {
    $id = createUser($this);

    $this->patchJson('/scim/v2/Users/'.$id, ['Operations' => [$operation]], $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidValue');

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('active', true);
})->with([
    'pathed' => [['op' => 'replace', 'path' => 'active', 'value' => 'fasle']],
    'pathless' => [['op' => 'replace', 'value' => ['active' => 'fasle']]],
]);

/**
 * Case folding is NOT coercion, and refusing it is not caution — it is an outage.
 * Microsoft Entra sends `{"op":"Replace","path":"active","value":"False"}` with a
 * capital F; Microsoft documents that as a client defect corrected only behind the
 * opt-in `?aadOptscim062020` flag, which existing provisioning jobs do not carry. A
 * byte-exact match 400s every termination push: the account stays active with live
 * sessions, and after repeated failures Entra quarantines the whole job.
 *
 * The refusals above are what keeps this honest — `"fasle"`, `"no"`, `1`, `0` and `"1"`
 * are still 400s.
 */
it('still accepts the boolean spellings SCIM defines, in any case', function (mixed $active, bool $expected): void {
    $id = createUser($this, ['active' => $active]);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('active', $expected);
})->with([
    'json true' => [true, true],
    'json false' => [false, false],
    'string true' => ['true', true],
    'string false' => ['false', false],
    'entra False' => ['False', false],
    'shouting TRUE' => ['TRUE', true],
    'padded' => [' false ', false],
]);

/**
 * The live regression in its exact wire shape: Entra's deactivation PATCH.
 */
it('deactivates on the capitalized active Entra actually sends', function (): void {
    $id = createUser($this);

    $this->patchJson('/scim/v2/Users/'.$id, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'Replace', 'path' => 'active', 'value' => 'False']],
    ], $this->scimHeaders)->assertOk()->assertJsonPath('active', false);

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('active', false);
});

it('defaults active to true when the attribute is absent', function (): void {
    $id = (string) $this->postJson('/scim/v2/Users', [
        'userName' => 'dana', 'externalId' => 'okta|1',
    ], $this->scimHeaders)->assertStatus(201)->json('id');

    $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk()->assertJsonPath('active', true);
});

// ---------------------------------------------------------------------------
// 6. userName equality must not depend on the database's collation.
// ---------------------------------------------------------------------------

/**
 * RFC 7643 defines `userName` as caseExact:false and ServiceProviderConfig advertises
 * it as uniqueness:"server". A case-SENSITIVE predicate broke both promises at once: on
 * a case-sensitive database the IdP's pre-provision lookup for `Dana.Rivera@corp.com`
 * returned nothing, the create-side collision check missed too, and a SECOND directory
 * row plus a second subject were minted for one human — invisible on MySQL's `_ci`
 * collations, which is why it survived.
 */
it('matches userName case-insensitively in a filter', function (): void {
    createUser($this, ['userName' => 'Dana.Rivera@corp.com']);

    foreach (['dana.rivera@corp.com', 'DANA.RIVERA@CORP.COM', 'Dana.Rivera@corp.com'] as $spelling) {
        $this->getJson('/scim/v2/Users?filter='.urlencode('userName eq "'.$spelling.'"'), $this->scimHeaders)
            ->assertOk()
            ->assertJsonPath('totalResults', 1)
            ->assertJsonPath('Resources.0.userName', 'Dana.Rivera@corp.com');
    }
});

it('refuses a duplicate userName that differs only in case', function (): void {
    createUser($this, ['userName' => 'Dana.Rivera@corp.com']);

    // A different externalId with the same name in a different case is the SAME
    // userName under uniqueness:"server" — a 409, not a second account.
    $this->postJson('/scim/v2/Users', [
        'userName' => 'dana.rivera@corp.com',
        'externalId' => 'okta|2',
        'emails' => [['value' => 'dana.two@corp.com', 'primary' => true]],
    ], $this->scimHeaders)
        ->assertStatus(409)
        ->assertJsonPath('scimType', 'uniqueness');

    expect(DirectoryUser::query()->count())->toBe(1);
});

it('matches an email filter case-insensitively', function (): void {
    createUser($this, ['emails' => [['value' => 'Dana.Rivera@Corp.com', 'primary' => true]]]);

    $this->getJson('/scim/v2/Users?filter='.urlencode('emails.value eq "dana.rivera@corp.com"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 1);
});

// ---------------------------------------------------------------------------
// 7. DELETE of an unknown id is a 404.
// ---------------------------------------------------------------------------

/**
 * A 204 told the IdP the deprovision succeeded for an id the server never had, so it
 * marked the user gone and stopped reconciling — silently orphaning whatever live
 * account that id was meant to name.
 */
it('returns 404 when deleting a user that does not exist', function (): void {
    $this->deleteJson('/scim/v2/Users/does-not-exist', [], $this->scimHeaders)
        ->assertStatus(404)
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('status', '404');
});

it('returns 404 when deleting a group that does not exist', function (): void {
    $this->deleteJson('/scim/v2/Groups/does-not-exist', [], $this->scimHeaders)
        ->assertStatus(404)
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');
});

it('still returns 204 when the delete actually happened', function (): void {
    $id = createUser($this);

    $this->deleteJson('/scim/v2/Users/'.$id, [], $this->scimHeaders)->assertStatus(204);
});

// ---------------------------------------------------------------------------
// 8. The throttle's 429 must stay inside the SCIM Error envelope.
// ---------------------------------------------------------------------------

/**
 * `throttle` used to run OUTSIDE the SCIM media-type middleware, so a rate-limited full
 * import received `{"message":"Too Many Attempts."}` as application/json. Okta and Entra
 * parse a SCIM response against the Error schema; an unparsable body is a fatal
 * connector fault to them, not "back off" — which is how a rate limit quarantines a
 * provisioning job instead of merely slowing it down.
 */
it('frames a throttled request as a SCIM error with its Retry-After intact', function (): void {
    $headers = $this->scimHeaders;

    $response = null;

    // The SCIM group is throttled at 120/min; the 121st request is the one under test.
    for ($i = 0; $i < 121; $i++) {
        $response = $this->getJson('/scim/v2/ServiceProviderConfig', $headers);

        if ($response->getStatusCode() === 429) {
            break;
        }
    }

    $response->assertStatus(429)
        ->assertHeader('Content-Type', 'application/scim+json')
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error')
        ->assertJsonPath('status', '429')
        ->assertJsonPath('detail', 'Too Many Attempts.');

    // Retry-After is the only thing telling the IdP how long to wait; re-framing the
    // body must not drop it.
    expect($response->headers->get('Retry-After'))->not->toBeNull();
});

// ---------------------------------------------------------------------------
// 9. The defensive 401 guard must not escape the SCIM error schema.
// ---------------------------------------------------------------------------

/**
 * Unreachable behind AuthenticateScim — which is exactly why it was left as
 * `abort(401)`, rendering Laravel's generic body. A guard that fires once, in
 * production, must still be readable by the client that trips it.
 */
it('frames the missing-directory guard as a SCIM error', function (): void {
    $call = fn () => app(UserController::class)->show(Request::create('/scim/v2/Users/x'), 'x');

    expect($call)->toThrow(HttpResponseException::class);

    try {
        $call();
    } catch (HttpResponseException $e) {
        $body = json_decode((string) $e->getResponse()->getContent(), true);

        expect($e->getResponse()->getStatusCode())->toBe(401)
            ->and($body['schemas'][0])->toBe('urn:ietf:params:scim:api:messages:2.0:Error')
            ->and($body['status'])->toBe('401')
            // RFC 6750 §3: a 401 names the scheme that failed. Without it a connector
            // sees an unclassified transport error, not "re-authenticate".
            ->and($e->getResponse()->headers->get('WWW-Authenticate'))->toStartWith('Bearer');
    }
});

it('challenges an unauthenticated SCIM request with the Bearer scheme', function (): void {
    $response = $this->getJson('/scim/v2/Users')->assertStatus(401);

    expect($response->headers->get('WWW-Authenticate'))->toStartWith('Bearer');
});

// ---------------------------------------------------------------------------
// 10. meta.created / meta.lastModified, and a filterable lastModified.
// ---------------------------------------------------------------------------

/**
 * Without them a connector cannot ask "what changed since", so every sync degrades to a
 * full sweep of the directory — on a schedule, straight into the rate limit above.
 */
it('emits meta.created and meta.lastModified on a user', function (): void {
    $id = createUser($this);

    $response = $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)->assertOk();
    $meta = $response->json('meta');

    expect($meta['resourceType'])->toBe('User')
        // RFC 7643 §3.1 defines meta.location as the URI of the resource, and
        // RFC 7644 §3.1 makes Content-Location carry the SAME value. A relative path
        // is neither, and a connector that follows it resolved it against its own base.
        ->and($meta['location'])->toBe(url('/scim/v2/Users/'.$id))
        ->and($response->headers->get('Content-Location'))->toBe($meta['location'])
        ->and($meta['created'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/')
        ->and($meta['lastModified'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/');
});

it('emits meta.created and meta.lastModified on a group', function (): void {
    $id = (string) $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $this->scimHeaders)
        ->assertStatus(201)->json('id');

    $response = $this->getJson('/scim/v2/Groups/'.$id, $this->scimHeaders)->assertOk();
    $meta = $response->json('meta');

    expect($meta['resourceType'])->toBe('Group')
        ->and($meta['location'])->toBe(url('/scim/v2/Groups/'.$id))
        ->and($response->headers->get('Content-Location'))->toBe($meta['location'])
        ->and($meta['created'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/')
        ->and($meta['lastModified'])->toMatch('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/');
});

it('answers the meta.lastModified delta-sync filter', function (): void {
    $this->travelTo('2026-07-01 12:00:00');
    createUser($this, ['userName' => 'old', 'externalId' => 'okta|old', 'emails' => [['value' => 'old@corp.com']]]);

    $this->travelTo('2026-07-20 12:00:00');
    createUser($this, ['userName' => 'new', 'externalId' => 'okta|new', 'emails' => [['value' => 'new@corp.com']]]);

    $this->travelBack();

    $this->getJson('/scim/v2/Users?filter='.urlencode('meta.lastModified gt "2026-07-10T00:00:00Z"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 1)
        ->assertJsonPath('Resources.0.userName', 'new');

    // The watermark is inclusive-exclusive as written: everything is newer than the epoch.
    $this->getJson('/scim/v2/Users?filter='.urlencode('meta.lastModified gt "2020-01-01T00:00:00Z"'), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', 2);
});

it('refuses an unparsable lastModified watermark instead of returning the wrong slice', function (): void {
    createUser($this);

    $this->getJson('/scim/v2/Users?filter='.urlencode('meta.lastModified gt "yesterday"'), $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter');
});

/**
 * The value the server HANDS OUT and the value it ACCEPTS must be in the same frame.
 *
 * Eloquent stores `updated_at` in `config('app.timezone')`; `meta.lastModified` is
 * emitted converted to UTC. Coercing the client's watermark with `->utc()` compared
 * those two directly, and they only agree at offset 0 — which is exactly what testbench
 * pins, so the entire suite was blind to this class of bug. Hence the explicit
 * non-UTC timezone here, in both directions:
 *
 *  - WEST of UTC (New York): a row modified 10:00 local is stored `10:00:00` and handed
 *    out as `14:00:00Z`. The returned watermark then compared `14:00:00 > 10:00:00` and
 *    every incremental sync answered 200 OK with zero rows — forever. Updates and
 *    deactivations silently stopped arriving.
 *  - EAST of UTC (Tokyo): the same mismatch inverts, and every cycle re-reads the whole
 *    directory instead — a full sweep on a schedule, into the rate limit.
 *
 * Both are checked against the server's OWN emitted value, which is what an IdP stores.
 */
it('compares a lastModified watermark in the timezone it emits it', function (string $timezone): void {
    config(['app.timezone' => $timezone]);
    date_default_timezone_set($timezone);

    $id = createUser($this);

    $watermark = (string) $this->getJson('/scim/v2/Users/'.$id, $this->scimHeaders)
        ->assertOk()->json('meta.lastModified');

    $filter = static fn (string $value): string => '/scim/v2/Users?filter='.urlencode('meta.lastModified gt "'.$value.'"');

    // Strictly newer than the watermark the IdP just stored: nothing. Answering here
    // is the east-of-UTC failure — a permanent full re-sync.
    $this->getJson($filter($watermark), $this->scimHeaders)->assertOk()->assertJsonPath('totalResults', 0);

    // One second before it: the user. Answering zero here is the west-of-UTC failure —
    // a delta sync that silently drops every change.
    $justBefore = CarbonImmutable::parse($watermark)->subSecond()->toIso8601ZuluString();

    $this->getJson($filter($justBefore), $this->scimHeaders)->assertOk()->assertJsonPath('totalResults', 1);
})->with([
    'west of UTC' => 'America/New_York',
    'east of UTC' => 'Asia/Tokyo',
    'at UTC' => 'UTC',
]);

// The timezone above is process-global; leave the suite as testbench configured it.
afterEach(function (): void {
    date_default_timezone_set('UTC');
});

// ---------------------------------------------------------------------------
// 11. /Groups must answer the filters IdPs actually send.
// ---------------------------------------------------------------------------

/**
 * Entra locates the group it already provisioned with `externalId eq "…"` on EVERY
 * cycle. Supporting only `displayName eq` returned a flat 400 to the first call of
 * every sync — and Entra escalates a hard failure into a quarantined provisioning job
 * rather than a degraded one.
 */
it('filters groups by the attributes IdPs query on', function (string $filter, int $expected): void {
    $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering', 'externalId' => 'entra|eng'], $this->scimHeaders)
        ->assertStatus(201);
    $this->postJson('/scim/v2/Groups', ['displayName' => 'Sales', 'externalId' => 'entra|sales'], $this->scimHeaders)
        ->assertStatus(201);

    $this->getJson('/scim/v2/Groups?filter='.urlencode($filter), $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('totalResults', $expected);
})->with([
    'externalId' => ['externalId eq "entra|eng"', 1],
    'externalId, folded attribute name' => ['externalid eq "entra|eng"', 1],
    'externalId with no match' => ['externalId eq "entra|nobody"', 0],
    'displayName' => ['displayName eq "Sales"', 1],
    'displayName, folded attribute name' => ['displayname eq "Sales"', 1],
]);

it('still refuses a group filter it cannot answer, rather than listing everything', function (): void {
    $this->postJson('/scim/v2/Groups', ['displayName' => 'Engineering'], $this->scimHeaders)->assertStatus(201);

    $this->getJson('/scim/v2/Groups?filter='.urlencode('members co "dana"'), $this->scimHeaders)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter');
});
