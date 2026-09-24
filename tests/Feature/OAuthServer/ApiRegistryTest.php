<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\OAuthServer\Contracts\Apis;
use Cbox\Id\OAuthServer\Exceptions\InvalidApiDefinition;
use Cbox\Id\OAuthServer\Models\ApiScope;
use Cbox\Id\OAuthServer\ValueObjects\ApiScopeDefinition;
use Cbox\Id\OAuthServer\ValueObjects\NewApi;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('registers an API with its scopes', function (): void {
    $api = $this->makeApi('https://tax.example.test', ['tax:read', 'tax:assess' => false], name: 'Tax');

    expect($api->identifier)->toBe('https://tax.example.test')
        ->and($api->environment_id)->toBe('env_test')
        ->and($api->isEnvironmentOwned())->toBeTrue()
        ->and($api->scopes->pluck('tenant_requestable', 'key')->all())->toBe(['tax:assess' => false, 'tax:read' => true]);

    $found = app(Apis::class)->identifiedBy('https://tax.example.test');
    expect($found?->id)->toBe($api->id);
});

it('refuses a malformed identifier, because it has to be something a client can name as resource', function (string $identifier): void {
    expect(fn () => $this->makeApi($identifier))
        ->toThrow(InvalidApiDefinition::class, 'must be an absolute URI');
})->with([
    'relative' => ['/api'],
    'no host' => ['urn:tax'],
    'fragment' => ['https://tax.example.test/#x'],
    'blank' => [''],
]);

it('keeps identifiers unique per environment and allows the same one in another', function (): void {
    $this->makeApi('https://tax.example.test');

    expect(fn () => $this->makeApi('https://tax.example.test'))
        ->toThrow(InvalidApiDefinition::class, 'already registered in this environment');

    $this->actingAsEnvironment('env_other');
    expect($this->makeApi('https://tax.example.test')->environment_id)->toBe('env_other');
});

it('keeps scope keys unique per environment, across APIs', function (): void {
    $this->makeApi('https://tax.example.test', ['shared:read']);

    expect(fn () => $this->makeApi('https://cadastre.example.test', ['shared:read']))
        ->toThrow(InvalidApiDefinition::class, 'already belongs to another API');

    // All or nothing: the refused API was not left behind without its scopes.
    expect(app(Apis::class)->identifiedBy('https://cadastre.example.test'))->toBeNull();

    // Another environment may use the key for its own API.
    $this->actingAsEnvironment('env_other');
    expect($this->makeApi('https://cadastre.example.test', ['shared:read'])->scopes)->toHaveCount(1);
});

it('refuses a scope the authorization server defines itself', function (string $scope): void {
    expect(fn () => $this->makeApi('https://tax.example.test', [$scope]))
        ->toThrow(InvalidApiDefinition::class, 'defined by the authorization server itself');
})->with(['openid', 'profile', 'email', 'offline_access', 'organizations', 'groups']);

it('refuses a scope key that is not an RFC 6749 scope-token', function (string $key): void {
    expect(fn () => $this->makeApi('https://tax.example.test', [$key]))
        ->toThrow(InvalidApiDefinition::class, 'is not a valid scope token');
})->with(['with space', 'quo"te', 'back\\slash', 'æøå']);

it('updates an existing scope in place when the API defines it again', function (): void {
    $api = $this->makeApi('https://tax.example.test', ['tax:read']);

    app(Apis::class)->defineScope($api, new ApiScopeDefinition('tax:read', 'Read returns', tenantRequestable: false));

    $row = ApiScope::query()->where('key', 'tax:read')->sole();
    expect($row->description)->toBe('Read returns')
        ->and($row->tenant_requestable)->toBeFalse();
});

it('removes a scope and deletes an API with its scopes', function (): void {
    $apis = app(Apis::class);
    $api = $this->makeApi('https://tax.example.test', ['tax:read', 'tax:write']);

    $apis->removeScope($api, 'tax:write');
    expect(ApiScope::query()->pluck('key')->all())->toBe(['tax:read']);

    $apis->delete($api);
    expect(ApiScope::query()->count())->toBe(0)
        ->and($apis->all())->toHaveCount(0);
});

it('lists APIs by owner', function (): void {
    $org = $this->makeOrganization();
    $this->makeApi('https://env.example.test', name: 'Env');
    $this->makeApi('https://org.example.test', organizationId: $org->id, name: 'Org');

    $apis = app(Apis::class);
    expect($apis->ownedBy(null)->pluck('name')->all())->toBe(['Env'])
        ->and($apis->ownedBy($org->id)->pluck('name')->all())->toBe(['Org'])
        ->and($apis->all()->pluck('name')->all())->toBe(['Env', 'Org']);
});

it('refuses an owner organization from another environment', function (): void {
    $this->actingAsEnvironment('env_other');
    $foreign = $this->makeOrganization('Elsewhere');
    $this->actingAsEnvironment('env_test');

    expect(fn () => $this->makeApi('https://tax.example.test', organizationId: $foreign->id))
        ->toThrow(CrossEnvironmentAccess::class);
});

it('links only an app with the same owner as the API', function (): void {
    $org = $this->makeOrganization();
    $platformApp = $this->makeClient(['openid']);
    $tenantApp = $this->makeClient(['openid'], organizationId: $org->id);

    // A tenant naming the platform's app as the enforcer of ITS api would receive the
    // platform app's roles for its users in every token audienced to it.
    expect(fn () => $this->makeApi('https://tenant.example.test', organizationId: $org->id, clientId: $platformApp->client->client_id))
        ->toThrow(InvalidApiDefinition::class, 'must have the same owner as the API');

    $api = $this->makeApi('https://tenant.example.test', organizationId: $org->id, clientId: $tenantApp->client->client_id);
    expect($api->client_id)->toBe($tenantApp->client->client_id);

    $envApi = $this->makeApi('https://env.example.test');
    expect(fn () => app(Apis::class)->linkClient($envApi, $tenantApp->client->client_id))
        ->toThrow(InvalidApiDefinition::class, 'must have the same owner as the API');

    expect(fn () => app(Apis::class)->linkClient($envApi, 'cid_nope'))
        ->toThrow(InvalidApiDefinition::class, 'No app with the client id');

    expect(app(Apis::class)->linkClient($envApi, $platformApp->client->client_id)->client_id)
        ->toBe($platformApp->client->client_id);
});

it('binds issuance reads to the named environment even with scoping suspended', function (): void {
    // A guard behind an already-scoped query can never fail. With the environment scope
    // suspended, only the WHERE clause stands between env_other's lookup and env_test's
    // API — so this is the test that proves the binding exists.
    $this->makeApi('https://tax.example.test', ['tax:read']);

    $apis = app(Apis::class);

    $this->withoutEnvironmentScope(function () use ($apis): void {
        expect($apis->registeredScopes('env_other', ['tax:read']))->toBe([])
            ->and($apis->audience('env_other', 'https://tax.example.test'))->toBeNull()
            ->and($apis->publicScopes('env_other'))->toBe([])
            ->and(array_keys($apis->registeredScopes('env_test', ['tax:read'])))->toBe(['tax:read'])
            ->and($apis->audience('env_test', 'https://tax.example.test')?->identifier)->toBe('https://tax.example.test');
    });
});

it('answers publicScopes with only environment-owned, tenant-requestable scopes', function (): void {
    $org = $this->makeOrganization();
    $this->makeApi('https://tax.example.test', ['tax:read', 'tax:assess' => false]);
    $this->makeApi('https://tenant.example.test', ['tenant:read'], organizationId: $org->id);

    expect(app(Apis::class)->publicScopes('env_test'))->toBe(['tax:read']);
});

it('registers through the contract with a typed definition', function (): void {
    $api = app(Apis::class)->register(new NewApi(
        identifier: 'https://cadastre.example.test/api',
        name: '  Cadastre  ',
        scopes: [new ApiScopeDefinition('cadastre:admin', 'Administer parcels', tenantRequestable: false)],
    ));

    expect($api->name)->toBe('Cadastre')
        ->and($api->scopes->sole()->description)->toBe('Administer parcels');
});
