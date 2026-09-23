<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\Organization\Contracts\CustomerApiKeys;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\OrganizationType;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\ValueObjects\ApiKeyActor;
use Cbox\Id\Organization\ValueObjects\NewCustomerApiKey;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Enums\EnvironmentApiScope;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/**
 * `POST /oauth/api-keys/verify`: an app (`ctx_live`), a holder who is an Admin of Acme
 * and holds the app's `Filer` role, and a key issued to them for that app.
 */
beforeEach(function (): void {
    $this->holder = $this->makeUser()->id;
    $this->org = app(Organizations::class)->create(new NewOrganization(
        name: 'Acme',
        slug: 'acme-'.Str::lower(Str::random(6)),
        type: OrganizationType::Customer,
    ));
    app(Memberships::class)->add($this->org->id, $this->holder, MembershipRole::Admin);

    $this->tax = $this->makeClient();
    $this->enableCustomerApiKeys($this->tax->client->client_id, 'ctx_live');

    $roles = app(Roles::class);
    $filer = $roles->define(null, 'Filer', null, $this->tax->client->client_id);
    $roles->grantPermission(null, $filer->id, 'returns:read');
    $roles->assign($this->org->id, $this->holder, $filer->id);

    $this->key = app(CustomerApiKeys::class)->issue(new NewCustomerApiKey(
        organizationId: $this->org->id,
        userId: $this->holder,
        clientId: $this->tax->client->client_id,
        permissions: ['returns:read'],
    ));
});

it('answers the contract body for a live key, authenticated with HTTP Basic', function (): void {
    $this->withBasicAuth($this->tax->client->client_id, $this->tax->secret)
        ->postJson('/oauth/api-keys/verify', ['key' => $this->key->plaintext])
        ->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertExactJson([
            'active' => true,
            'key_id' => $this->key->key->id,
            'sub' => $this->holder,
            'org' => $this->org->id,
            'org_role' => 'admin',
            'permissions' => ['returns:read'],
            'client_id' => $this->tax->client->client_id,
            'expires_at' => null,
        ]);
});

it('accepts client credentials in the body too', function (): void {
    $this->postJson('/oauth/api-keys/verify', [
        'client_id' => $this->tax->client->client_id,
        'client_secret' => $this->tax->secret,
        'key' => $this->key->plaintext,
    ])->assertOk()->assertJsonPath('active', true);
});

it('refuses a caller that does not authenticate as a confidential client', function (): void {
    $this->postJson('/oauth/api-keys/verify', ['key' => $this->key->plaintext])
        ->assertStatus(401)
        ->assertExactJson(['error' => 'invalid_client']);

    $this->withBasicAuth($this->tax->client->client_id, 'wrong-secret')
        ->postJson('/oauth/api-keys/verify', ['key' => $this->key->plaintext])
        ->assertStatus(401);

    // A public client has no credential to prove, so it cannot verify anything.
    $public = $this->makeClient(type: ClientType::Public);

    $this->postJson('/oauth/api-keys/verify', ['client_id' => $public->client->client_id, 'key' => $this->key->plaintext])
        ->assertStatus(401);
})->group('security');

/*
 * One answer for every failure: the body is byte-for-byte the same whether the key is
 * another app's, revoked, unknown or malformed, so nothing can be learned by probing.
 */
it('answers exactly {active:false} for another app\'s key and for every other failure', function (): void {
    $other = $this->makeClient();
    $this->enableCustomerApiKeys($other->client->client_id, 'other_live');

    $verify = fn (string $key, object $as) => $this->withBasicAuth($as->client->client_id, $as->secret)
        ->postJson('/oauth/api-keys/verify', ['key' => $key]);

    $verify($this->key->plaintext, $other)->assertOk()->assertExactJson(['active' => false]);
    $verify('ctx_live_'.str_repeat('x', 48), $this->tax)->assertOk()->assertExactJson(['active' => false]);
    $verify('not-a-key', $this->tax)->assertOk()->assertExactJson(['active' => false]);

    $this->withBasicAuth($this->tax->client->client_id, $this->tax->secret)
        ->postJson('/oauth/api-keys/verify', [])
        ->assertOk()->assertExactJson(['active' => false]);

    app(CustomerApiKeys::class)->revoke($this->key->key->id, ApiKeyActor::user($this->holder));
    $verify($this->key->plaintext, $this->tax)->assertOk()->assertExactJson(['active' => false]);
})->group('security');

it('is registered behind the configured throttle', function (): void {
    $route = collect(Route::getRoutes()->getRoutes())
        ->first(fn ($route) => $route->uri() === 'oauth/api-keys/verify');

    expect($route)->not->toBeNull()
        ->and($route->methods())->toContain('POST')
        ->and($route->gatherMiddleware())->toContain('throttle:600,1');
});

/*
 * BACK-COMPAT. The personal-token introspection endpoint neither accepts a customer key
 * nor stops accepting personal tokens.
 */
it('keeps personal-token introspection to personal tokens', function (): void {
    $pat = app(UserApiTokens::class)->issue($this->org->id, $this->holder, 'CLI', TokenScope::Read);
    $envKey = app(EnvironmentApiKeys::class)->issue('env_test', 'rp', EnvironmentApiScope::all());

    $this->withToken($envKey->plaintext)
        ->postJson('/user-tokens/introspect', ['token' => $this->key->plaintext])
        ->assertOk()->assertExactJson(['active' => false]);

    $this->withToken($envKey->plaintext)
        ->postJson('/user-tokens/introspect', ['token' => $pat->plaintext])
        ->assertOk()->assertJsonPath('active', true)->assertJsonPath('scope', 'read');

    // …and a personal token is not a customer key.
    $this->withBasicAuth($this->tax->client->client_id, $this->tax->secret)
        ->postJson('/oauth/api-keys/verify', ['key' => $pat->plaintext])
        ->assertOk()->assertExactJson(['active' => false]);
});

/*
 * An app linked to a registered API (FC) verifies its keys exactly as before: the key is
 * bound to the app's client_id, the API names that same client_id for its roles, and the
 * permissions are re-capped against that app's roles. Registering the API must neither
 * break verification nor let a different client — the API's other callers — read the key.
 */
it('verifies a key for an app linked to a registered API through that app\'s credentials', function (): void {
    $this->makeApi('https://tax.example.test', ['returns:read'], clientId: $this->tax->client->client_id);
    $gateway = $this->makeClient(['returns:read']);

    $this->withBasicAuth($this->tax->client->client_id, $this->tax->secret)
        ->postJson('/oauth/api-keys/verify', ['key' => $this->key->plaintext])
        ->assertOk()
        ->assertJsonPath('active', true)
        ->assertJsonPath('client_id', $this->tax->client->client_id)
        ->assertJsonPath('permissions', ['returns:read']);

    // A client holding the API's scope is not the API's app: it cannot read the key.
    $this->withBasicAuth($gateway->client->client_id, $gateway->secret)
        ->postJson('/oauth/api-keys/verify', ['key' => $this->key->plaintext])
        ->assertOk()
        ->assertExactJson(['active' => false]);
})->group('security');

it('keeps verifying through the old secret and the new one while a rotation overlaps', function (): void {
    $this->makeApi('https://tax.example.test', ['returns:read'], clientId: $this->tax->client->client_id);
    $rotated = app(ClientRegistry::class)->rotateSecret($this->tax->client, 3600);

    foreach ([$this->tax->secret, $rotated->secret] as $secret) {
        $this->withBasicAuth($this->tax->client->client_id, $secret)
            ->postJson('/oauth/api-keys/verify', ['key' => $this->key->plaintext])
            ->assertOk()
            ->assertJsonPath('active', true);
    }
});
