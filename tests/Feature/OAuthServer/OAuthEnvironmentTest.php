<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\NewClient;
use Cbox\Id\Organization\Models\Organization;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * The OAuth surface (clients, connections, directories, and opaque codes/tokens)
 * is environment-owned: a client registered in one environment cannot be found —
 * and therefore cannot authenticate — from another.
 */
it('scopes oauth clients to their environment', function (): void {
    $make = fn (string $env, string $cid) => $this->runAsEnvironment($env, fn () => Client::create([
        'organization_id' => 'org_1', 'client_id' => $cid, 'name' => 'App',
        'type' => 'confidential', 'redirect_uris' => [], 'grant_types' => ['client_credentials'],
        'scopes' => ['openid'], 'first_party' => false, 'secret_hash' => 'x',
    ]));
    $make('env_a', 'cid_a');
    $make('env_b', 'cid_b');

    $this->actingAsEnvironment('env_a');
    expect(Client::pluck('client_id')->all())->toBe(['cid_a'])
        ->and(Client::where('client_id', 'cid_b')->exists())->toBeFalse();

    // Auto-stamped on create.
    expect(Client::first()->environment_id)->toBe('env_a');
});

/**
 * @group isolation
 *
 * Issued access-token records (revocation/introspection state) are
 * environment-owned: a token minted in one environment cannot be found — and
 * therefore never revoked or introspected — from another, even by its jti or
 * primary key.
 */
it('scopes access-token records to their environment', function (): void {
    $token = $this->runAsEnvironment('env_a', fn () => AccessToken::create([
        'jti' => 'jti-a', 'client_id' => 'cid_a', 'scopes' => ['openid'],
        'expires_at' => Carbon::now()->addHour(),
    ]));

    // Auto-stamped on create.
    expect($token->environment_id)->toBe('env_a');

    // From env_b the record is invisible — by jti and by primary key.
    $this->runAsEnvironment('env_b', function () use ($token): void {
        expect(AccessToken::count())->toBe(0)
            ->and(AccessToken::where('jti', 'jti-a')->exists())->toBeFalse()
            ->and(AccessToken::find($token->id))->toBeNull();
    });

    // From env_a it is still reachable, proving it exists (just isolated).
    $this->runAsEnvironment('env_a', fn () => expect(AccessToken::find($token->id))->not->toBeNull());
})->group('isolation');
/**
 * THE ENVIRONMENT STAMP AND THE NAMED OWNER ARE WRITTEN SIDE BY SIDE, AND NOTHING
 * CHECKED THEY AGREE.
 *
 * `EnvironmentScope` stamps a new row with the ambient environment and fences reads by
 * it. It never looks at the `organization_id` beside the stamp — so a caller in E1
 * supplying an organization that lives in E2 got a row stamped E1 claiming a tenant of
 * E2. For an OAuth client that is not a bookkeeping oddity: `client_credentials` would
 * mint E1's `iss` carrying E2's `org`, and every relying party downstream reads `org` as
 * the tenant the token speaks for.
 *
 * `MembershipService::add()` refused this from the beginning; the other writers of an
 * `organization_id` did not. `OwnerEnvironment` is that check, shared.
 */
it('refuses to register a client owned by another environment\'s organization', function (): void {
    // Created from INSIDE the other environment — the model's own guard refuses a row
    // stamped elsewhere, which is the boundary working one layer down.
    $this->actingAsEnvironment('env_b');
    $foreign = Organization::query()->create(['name' => 'Theirs', 'slug' => 'theirs']);

    $this->actingAsEnvironment('env_a');

    expect(fn () => app(ClientRegistry::class)->register(new NewClient(
        'Sneaky', ClientType::Confidential, redirectUris: [], scopes: ['api.read'],
        organizationId: $foreign->id,
    )))->toThrow(CrossEnvironmentAccess::class);
})->group('security');

/**
 * And the ordinary case is untouched: an organization of THIS environment registers
 * normally, and so does a client with no organization at all — an environment-wide client
 * is a real shape, not a missing owner.
 */
it('still registers a client for a local organization, and for none', function (): void {
    $this->actingAsEnvironment('env_a');
    $local = Organization::query()->create(['name' => 'Mine', 'slug' => 'mine', 'environment_id' => 'env_a']);

    $owned = app(ClientRegistry::class)->register(new NewClient(
        'Mine', ClientType::Confidential, redirectUris: [], scopes: ['api.read'],
        organizationId: $local->id,
    ));

    $shared = app(ClientRegistry::class)->register(new NewClient(
        'Environment-wide', ClientType::Confidential, redirectUris: [], scopes: ['api.read'],
    ));

    expect($owned->client->organization_id)->toBe($local->id)
        ->and($shared->client->organization_id)->toBeNull();
});
