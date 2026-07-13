<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @return array<string, string>
 */
function scimHeaders(string $token): array
{
    return ['Authorization' => 'Bearer '.$token];
}

it('rejects SCIM requests without a valid bearer token', function (): void {
    $this->postJson('/scim/v2/Users', ['userName' => 'x'])->assertStatus(401);
    $this->postJson('/scim/v2/Users', ['userName' => 'x'], ['Authorization' => 'Bearer scim_wrong'])->assertStatus(401);
});

it('provisions a user via SCIM POST', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeDirectory($org->id);

    $this->postJson('/scim/v2/Users', [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User'],
        'userName' => 'dana',
        'externalId' => 'okta|1',
        'emails' => [['value' => 'dana@corp.com', 'primary' => true]],
        'active' => true,
    ], scimHeaders($registered->token))
        ->assertStatus(201)
        ->assertJsonPath('userName', 'dana')
        ->assertJsonPath('externalId', 'okta|1')
        ->assertJsonPath('active', true);

    $this->assertDatabaseHas('directory_users', ['external_id' => 'okta|1']);
});

it('reads, deactivates via PATCH and deletes a user', function (): void {
    $org = $this->makeOrganization();
    $headers = scimHeaders($this->makeDirectory($org->id)->token);

    $id = $this->postJson('/scim/v2/Users', [
        'userName' => 'dana', 'externalId' => 'okta|1', 'emails' => [['value' => 'dana@corp.com']],
    ], $headers)->json('id');

    $this->getJson('/scim/v2/Users/'.$id, $headers)->assertOk()->assertJsonPath('id', $id);

    $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'value' => ['active' => false]]],
    ], $headers)->assertOk()->assertJsonPath('active', false);

    $this->deleteJson('/scim/v2/Users/'.$id, [], $headers)->assertStatus(204);
});

it('provisions and returns the Enterprise User extension', function (): void {
    $org = $this->makeOrganization();
    $headers = scimHeaders($this->makeDirectory($org->id)->token);
    $urn = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

    // NB: assert against the decoded array by literal key — assertJsonPath splits
    // on dots, which the "2.0" in the extension URN would break.
    $body = $this->postJson('/scim/v2/Users', [
        'schemas' => ['urn:ietf:params:scim:schemas:core:2.0:User', $urn],
        'userName' => 'dana',
        'externalId' => 'okta|1',
        $urn => [
            'employeeNumber' => 'E-42',
            'department' => 'Engineering',
            'costCenter' => 'CC-100',
            'manager' => ['value' => 'mgr-1', 'displayName' => 'Grace'],
            'ignored' => 'dropped',
        ],
    ], $headers)->assertStatus(201)->json();

    expect($body[$urn]['employeeNumber'])->toBe('E-42')
        ->and($body[$urn]['department'])->toBe('Engineering')
        ->and($body[$urn]['costCenter'])->toBe('CC-100')
        ->and($body[$urn]['manager']['displayName'])->toBe('Grace')
        ->and($body[$urn])->not->toHaveKey('ignored')   // unknown attrs dropped
        ->and($body['schemas'])->toContain($urn);        // extension advertised
});

it('patches an enterprise attribute via a fully-qualified path', function (): void {
    $org = $this->makeOrganization();
    $headers = scimHeaders($this->makeDirectory($org->id)->token);
    $urn = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

    $id = $this->postJson('/scim/v2/Users', [
        'userName' => 'dana', 'externalId' => 'okta|1',
        $urn => ['department' => 'Sales'],
    ], $headers)->json('id');

    $body = $this->patchJson('/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'path' => $urn.':department', 'value' => 'Engineering']],
    ], $headers)->assertOk()->json();

    expect($body[$urn]['department'])->toBe('Engineering');
});

it('returns 404 for an unknown user', function (): void {
    $headers = scimHeaders($this->makeDirectory($this->makeOrganization()->id)->token);

    $this->getJson('/scim/v2/Users/nonexistent', $headers)->assertStatus(404);
});

it('deprovision over SCIM revokes the user session end-to-end', function (): void {
    $org = $this->makeOrganization();
    $headers = scimHeaders($this->makeDirectory($org->id)->token);

    $id = $this->postJson('/scim/v2/Users', [
        'userName' => 'dana', 'externalId' => 'okta|1', 'emails' => [['value' => 'dana@corp.com']],
    ], $headers)->json('id');

    $userId = (string) DirectoryUser::query()->firstOrFail()->user_id;
    $session = app(SessionManager::class)->start($userId, $org->id, ['sso']);

    $this->deleteJson('/scim/v2/Users/'.$id, [], $headers)->assertStatus(204);

    expect(app(SessionManager::class)->active($session->id))->toBeNull();
});

it('returns 409 when the SCIM email already belongs to an account', function (): void {
    $org = $this->makeOrganization();
    $headers = scimHeaders($this->makeDirectory($org->id)->token);
    app(Subjects::class)->create('taken@corp.com', 'Taken', 'pw12345678');

    $this->postJson('/scim/v2/Users', [
        'userName' => 'taken', 'externalId' => 'ext|9', 'emails' => [['value' => 'taken@corp.com']],
    ], $headers)
        ->assertStatus(409)
        ->assertJsonPath('scimType', 'uniqueness');
});
