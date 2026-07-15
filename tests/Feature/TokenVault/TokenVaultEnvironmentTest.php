<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Exceptions\EnvironmentMissing;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @group isolation
 *
 * Vault secrets and grants are environment-owned, so a credential stored in one
 * environment is structurally invisible — and un-leasable — in any other.
 */
it('refuses to store when no environment is in context', function (): void {
    $this->forgetEnvironment();

    $this->storeVaultSecret('openai', 'openai', 'sk-live-x');
})->throws(EnvironmentMissing::class);

it('cannot lease a secret from another environment', function (): void {
    // Store + grant inside env_a.
    $secretId = $this->runAsEnvironment('env_a', function (): string {
        $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-x');
        $this->grantVaultAccess($secret->id, 'agent-client-1');

        return $secret->id;
    });

    // The same id, same client, in env_b: the hard scope hides the secret AND the
    // grant, so it is a uniform LeaseDenied.
    $this->runAsEnvironment('env_b', function () use ($secretId): void {
        expect(fn () => $this->leaseVaultSecret($secretId, 'agent-client-1'))
            ->toThrow(LeaseDenied::class);
    });

    // It still leases in its own environment.
    $lease = $this->runAsEnvironment('env_a', fn () => $this->leaseVaultSecret($secretId, 'agent-client-1'));
    expect($lease->secret)->toBe('sk-live-x');
})->group('isolation');

it('auto-stamps the environment on the secret row and hides it cross-env', function (): void {
    $secretId = $this->runAsEnvironment('env_a', fn () => $this->storeVaultSecret('openai', 'openai', 'sk-live-x')->id);

    $stored = $this->runAsEnvironment('env_a', fn () => VaultSecret::query()->whereKey($secretId)->firstOrFail());
    expect($stored->environment_id)->toBe('env_a');

    // Invisible from env_b, even by primary key.
    $this->runAsEnvironment('env_b', function () use ($secretId): void {
        expect(VaultSecret::query()->whereKey($secretId)->first())->toBeNull();
    });
})->group('isolation');
