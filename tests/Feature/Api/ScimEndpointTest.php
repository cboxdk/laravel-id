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
