<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
