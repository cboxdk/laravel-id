<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\Client;
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
