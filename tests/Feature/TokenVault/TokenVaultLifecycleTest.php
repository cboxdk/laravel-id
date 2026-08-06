<?php

declare(strict_types=1);

use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('stores, grants, and leases a secret back to an authorized agent', function (): void {
    $secret = $this->storeVaultSecret('openai-prod', 'openai', 'sk-live-abc123');
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    $lease = $this->leaseVaultSecret($secret->id, 'agent-client-1', 'summarize-ticket');

    expect($lease->secret)->toBe('sk-live-abc123')
        ->and($lease->provider)->toBe('openai')
        ->and($lease->secretId)->toBe($secret->id)
        ->and($lease->expiresAt->getTimestamp())->toBeGreaterThan(now()->getTimestamp());
});

it('leases the rotated value after rotation', function (): void {
    $secret = $this->storeVaultSecret('github', 'github', 'ghp_old');
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    app(SecretVault::class)->rotate($secret->id, 'ghp_new', null);

    $lease = $this->leaseVaultSecret($secret->id, 'agent-client-1');
    expect($lease->secret)->toBe('ghp_new');
});

it('refuses to lease a revoked secret', function (): void {
    $secret = $this->storeVaultSecret('stripe', 'stripe', 'sk_live_x');
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    app(SecretVault::class)->revoke($secret->id, null);

    $this->leaseVaultSecret($secret->id, 'agent-client-1');
})->throws(LeaseDenied::class);

it('refuses to lease an expired secret', function (): void {
    $secret = $this->storeVaultSecret('short-lived', 'openai', 'sk-live-x', null, null);
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    // Push the stored secret past its expiry.
    $secret->forceFill(['expires_at' => now()->subMinute()])->save();

    $this->leaseVaultSecret($secret->id, 'agent-client-1');
})->throws(LeaseDenied::class);

it('caps the lease window by the per-grant max, never above the vault ceiling', function (): void {
    config()->set('cbox-id.token_vault.default_lease_ttl_seconds', 300);
    app()->forgetInstance(SecretVault::class);

    $secret = $this->storeVaultSecret('capped', 'openai', 'sk-live-x');
    $this->grantVaultAccess($secret->id, 'agent-client-1', maxTtlSeconds: 30);

    $lease = $this->leaseVaultSecret($secret->id, 'agent-client-1');

    // 30s grant cap wins over the 300s default; the window is at most ~30s out.
    expect($lease->expiresAt->getTimestamp())->toBeLessThanOrEqual(now()->addSeconds(31)->getTimestamp());
});

it('rotating an unknown secret is a management error, not a uniform denial', function (): void {
    app(SecretVault::class)->rotate('01VAULTNONEXISTENT000000000', 'x', null);
})->throws(SecretNotFound::class);
