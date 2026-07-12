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

it('rejects an unsupported filter with invalidFilter', function (): void {
    $headers = $this->scimHeaders;

    $this->getJson('/scim/v2/Users?filter='.urlencode('emails[type eq "work"] pr and userName sw "x"'), $headers)
        ->assertStatus(400)
        ->assertJsonPath('scimType', 'invalidFilter');
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
