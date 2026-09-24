<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\ServiceAccounts;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGrantable;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\ClientAudit;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * A registered scope may be granted to a client only when the client's owner may hold it.
 * The rule is enforced when the client is SAVED — whoever saves it — and again at the
 * token endpoint (tests/Feature/Api/ApiAudienceTest.php).
 */

beforeEach(function (): void {
    $this->makeApi('https://tax.example.test', ['tax:read', 'tax:assess' => false]);
});

it('refuses to register a tenant client holding a scope the environment kept for itself', function (): void {
    $org = $this->makeOrganization();

    try {
        $this->makeClient(['openid', 'tax:read', 'tax:assess', 'free:text'], organizationId: $org->id);
        $this->fail('a tenant client was registered holding tax:assess');
    } catch (ScopeNotGrantable $e) {
        expect($e->scopes)->toBe(['tax:assess'])
            ->and($e->getMessage())->toStartWith('The scope(s) tax:assess belong to a registered API this client may not hold.');
    }

    expect(Client::query()->where('organization_id', $org->id)->exists())->toBeFalse();
});

it('registers a tenant client with tenant-requestable and free-text scopes', function (): void {
    $org = $this->makeOrganization();

    $client = $this->makeClient(['openid', 'tax:read', 'free:text'], organizationId: $org->id);

    expect($client->client->scopes)->toBe(['openid', 'tax:read', 'free:text']);
});

it('lets an environment-owned client hold any registered scope', function (): void {
    expect($this->makeClient(['tax:assess'])->client->scopes)->toBe(['tax:assess']);
});

it('refuses an update that ADDS a scope the owner may not hold, whoever writes it', function (): void {
    $org = $this->makeOrganization();
    $client = Client::query()->findOrFail($this->makeClient(['tax:read'], organizationId: $org->id)->client->id);

    // The way a console edits scopes: set the attribute, save. No registry in sight.
    $client->scopes = ['tax:read', 'tax:assess'];

    expect(fn () => $client->save())->toThrow(ScopeNotGrantable::class, 'The scope(s) tax:assess belong to');
    expect(Client::query()->findOrFail($client->id)->scopes)->toBe(['tax:read']);
});

it('re-judges every held scope when the owner changes', function (): void {
    $org = $this->makeOrganization();
    $client = Client::query()->findOrFail($this->makeClient(['tax:assess'])->client->id);

    // Handing an operator-owned client to a tenant must not carry tax:assess with it.
    $client->organization_id = $org->id;

    expect(fn () => $client->save())->toThrow(ScopeNotGrantable::class, 'The scope(s) tax:assess belong to');
});

it('refuses a service account holding a scope its organization may not hold', function (): void {
    $org = $this->makeOrganization();

    expect(fn () => app(ServiceAccounts::class)->create($org->id, 'Bot', ['tax:assess']))
        ->toThrow(ScopeNotGrantable::class, 'The scope(s) tax:assess belong to');
});

it("refuses a tenant client a scope of another tenant's API, and grants the owner's", function (): void {
    $owner = $this->makeOrganization('Owner');
    $other = $this->makeOrganization('Other');
    $this->makeApi('https://books.example.test', ['books:read'], organizationId: $owner->id);

    expect(fn () => $this->makeClient(['books:read'], organizationId: $other->id))
        ->toThrow(ScopeNotGrantable::class, 'The scope(s) books:read belong to');

    expect($this->makeClient(['books:read'], organizationId: $owner->id)->client->scopes)->toBe(['books:read']);
});

it('treats a dynamically registered client as a tenant, not as the environment', function (): void {
    $registered = app(ClientRegistry::class)->register(new NewClient('Operator app', scopes: ['tax:assess']));
    $client = Client::query()->findOrFail($registered->client->id);

    // Becoming self-registered re-judges what it holds: null owner is not trust.
    $client->registration_access_token_hash = hash('sha256', 'reg_x');

    expect(fn () => $client->save())->toThrow(ScopeNotGrantable::class, 'The scope(s) tax:assess belong to');
});

/*
 * The registry's own write paths — register, update and blueprint import — all reach the
 * model's save, so the ownership rule holds through each of them. Proven per path, because
 * a registry that ever switches one of them to a query-level write would skip the hook.
 */

it('refuses a registry update that adds a scope the owner may not hold, and records nothing', function (): void {
    $org = $this->makeOrganization();
    $registry = app(ClientRegistry::class);
    $client = Client::query()->findOrFail($this->makeClient(['tax:read'], organizationId: $org->id)->client->id);
    $audit = $this->fakeAudit();

    $settings = $registry->blueprint($client)->withScopes(['tax:read', 'tax:assess']);

    expect(fn () => $registry->update($client, $settings))
        ->toThrow(ScopeNotGrantable::class, 'The scope(s) tax:assess belong to');

    expect(Client::query()->findOrFail($client->id)->scopes)->toBe(['tax:read'])
        ->and(array_map(fn (AuditEvent $e): string => $e->action, $audit->recorded))->not->toContain(ClientAudit::UPDATED);
});

it('lets a registry update keep a scope the client already held when its API was registered', function (): void {
    $org = $this->makeOrganization();
    $registered = $this->makeClient(['legacy:scope'], organizationId: $org->id);
    $this->makeApi('https://legacy.example.test', ['legacy:scope' => false]);
    $registry = app(ClientRegistry::class);
    $client = Client::query()->findOrFail($registered->client->id);

    $registry->update($client, $registry->blueprint($client)->withName('Renamed'));

    expect(Client::query()->findOrFail($client->id)->name)->toBe('Renamed');
});

it('refuses to import a blueprint into an organization that may not hold its scopes', function (): void {
    $org = $this->makeOrganization();
    $registry = app(ClientRegistry::class);
    $blueprint = $registry->blueprint($this->makeClient(['tax:assess'])->client);

    expect(fn () => $registry->import($blueprint, $org->id))
        ->toThrow(ScopeNotGrantable::class, 'The scope(s) tax:assess belong to');

    expect(Client::query()->where('organization_id', $org->id)->exists())->toBeFalse();

    // The same blueprint imports as an environment-owned app, which may hold it.
    expect($registry->import($blueprint)->client->scopes)->toBe(['tax:assess']);
});
