<?php

declare(strict_types=1);

use Cbox\Id\Directory\Models\DirectoryUser;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * The environment is the hard outer boundary, and SCIM is the surface most likely to
 * cross it by accident: it is machine-to-machine, authenticated by a long-lived bearer
 * token, and every resource is addressed by an opaque id that means nothing until the
 * server resolves it. Nothing in a SCIM request names the tenant — so if the directory
 * lookup or the resource lookup ever escapes the environment scope, a customer's IdP
 * reads and rewrites ANOTHER customer's users, and every one of those writes is
 * recorded as a legitimate provisioning event.
 *
 * The suite had no test for it at all: the boundary was assumed, not asserted.
 */
beforeEach(function (): void {
    // Two tenants on two hosts — the shape ResolveEnvironment sees in production.
    $this->alpha = Environment::create(['name' => 'Alpha', 'slug' => 'alpha', 'domain' => 'alpha.id.test']);
    $this->beta = Environment::create(['name' => 'Beta', 'slug' => 'beta', 'domain' => 'beta.id.test']);

    // No default plane: an unresolved host must not silently fall back to one.
    config(['cbox-id.environments.default' => null]);

    $this->alphaDirectory = $this->runAsEnvironment($this->alpha->id, fn () => $this->makeDirectory($this->makeOrganization('Alpha Inc')->id));
    $this->betaDirectory = $this->runAsEnvironment($this->beta->id, fn () => $this->makeDirectory($this->makeOrganization('Beta Inc')->id));

    $this->alphaUserId = (string) $this->postJson('http://alpha.id.test/scim/v2/Users', [
        'userName' => 'dana@alpha.test',
        'externalId' => 'okta|alpha-1',
        'emails' => [['value' => 'dana@alpha.test', 'primary' => true]],
        'active' => true,
    ], ['Authorization' => 'Bearer '.$this->alphaDirectory->token])->assertStatus(201)->json('id');
});

it('provisions each environment into its own directory', function (): void {
    // Sanity: the fixture actually created a cross-environment target to attack.
    $this->runAsEnvironment($this->alpha->id, function (): void {
        expect(DirectoryUser::query()->count())->toBe(1);
    });

    $this->runAsEnvironment($this->beta->id, function (): void {
        expect(DirectoryUser::query()->count())->toBe(0);
    });
})->group('isolation');

it('refuses a SCIM token from another environment outright', function (): void {
    // Environment A's token presented on environment B's host must not authenticate:
    // the directory row itself is environment-owned, so it is not even visible there.
    $this->getJson('http://beta.id.test/scim/v2/Users', ['Authorization' => 'Bearer '.$this->alphaDirectory->token])
        ->assertStatus(401)
        ->assertJsonPath('schemas.0', 'urn:ietf:params:scim:api:messages:2.0:Error');
})->group('isolation');

it('never lists another environment\'s users', function (): void {
    $headers = ['Authorization' => 'Bearer '.$this->betaDirectory->token];

    $this->getJson('http://beta.id.test/scim/v2/Users', $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);

    // Not by filter either — the filter must never widen past the environment scope.
    $this->getJson('http://beta.id.test/scim/v2/Users?filter='.urlencode('userName eq "dana@alpha.test"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);

    $this->getJson('http://beta.id.test/scim/v2/Users?filter='.urlencode('externalId eq "okta|alpha-1"'), $headers)
        ->assertOk()
        ->assertJsonPath('totalResults', 0);
})->group('isolation');

it('cannot READ another environment\'s user by its id', function (): void {
    // The id is the only thing an attacker needs to guess or leak. It must resolve to
    // nothing outside the environment that owns it — a 404, not the resource.
    $this->getJson('http://beta.id.test/scim/v2/Users/'.$this->alphaUserId, [
        'Authorization' => 'Bearer '.$this->betaDirectory->token,
    ])->assertStatus(404);
})->group('isolation');

it('cannot PATCH another environment\'s user', function (): void {
    // The write that matters: a cross-tenant `active:false` would deactivate a stranger's
    // employee, drop their org membership and revoke every session they hold.
    $this->patchJson('http://beta.id.test/scim/v2/Users/'.$this->alphaUserId, [
        'schemas' => ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
        'Operations' => [['op' => 'replace', 'path' => 'active', 'value' => false]],
    ], ['Authorization' => 'Bearer '.$this->betaDirectory->token])->assertStatus(404);

    $this->runAsEnvironment($this->alpha->id, function (): void {
        expect(DirectoryUser::query()->firstOrFail()->active)->toBeTrue();
    });
})->group('isolation');

it('cannot PUT or DELETE another environment\'s user', function (): void {
    $headers = ['Authorization' => 'Bearer '.$this->betaDirectory->token];

    $this->putJson('http://beta.id.test/scim/v2/Users/'.$this->alphaUserId, [
        'userName' => 'hijacked', 'active' => false,
    ], $headers)->assertStatus(404);

    $this->deleteJson('http://beta.id.test/scim/v2/Users/'.$this->alphaUserId, [], $headers)
        ->assertStatus(404);

    $this->runAsEnvironment($this->alpha->id, function (): void {
        $user = DirectoryUser::query()->firstOrFail();

        expect($user->active)->toBeTrue()
            ->and($user->resource['userName'])->toBe('dana@alpha.test');
    });
})->group('isolation');

it('still serves the owning environment', function (): void {
    // The boundary must deny the neighbour without denying the owner — a test that only
    // asserts 404s passes just as well on a completely broken endpoint.
    $this->getJson('http://alpha.id.test/scim/v2/Users/'.$this->alphaUserId, [
        'Authorization' => 'Bearer '.$this->alphaDirectory->token,
    ])->assertOk()->assertJsonPath('userName', 'dana@alpha.test');
})->group('isolation');
