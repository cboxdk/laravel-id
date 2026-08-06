<?php

declare(strict_types=1);

use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * The vault is deny-by-default: no live grant, no lease. Every refusal is the
 * SAME LeaseDenied so a caller cannot tell an ungranted secret from a nonexistent
 * one and use the vault as an enumeration oracle.
 */
it('refuses a lease with no grant', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-x');

    // Stored, but this client was never granted access.
    $this->leaseVaultSecret($secret->id, 'agent-client-1');
})->throws(LeaseDenied::class);

it('refuses a lease after the grant is revoked', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-x');
    $this->grantVaultAccess($secret->id, 'agent-client-1');
    app(SecretVault::class)->revokeGrant($secret->id, 'agent-client-1', null);

    $this->leaseVaultSecret($secret->id, 'agent-client-1');
})->throws(LeaseDenied::class);

it('does not let one agent lease another agent grant', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-x');
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    // A different client with no grant of its own is refused.
    $this->leaseVaultSecret($secret->id, 'agent-client-2');
})->throws(LeaseDenied::class);

it('refuses an unknown secret with the same uniform denial (no oracle)', function (): void {
    // A nonexistent secret id fails exactly like an ungranted one — LeaseDenied,
    // never SecretNotFound, so existence cannot be probed on the lease path.
    $this->leaseVaultSecret('01VAULTNONEXISTENT000000000', 'agent-client-1');
})->throws(LeaseDenied::class);

it('re-granting a revoked pair restores access', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-x');
    $this->grantVaultAccess($secret->id, 'agent-client-1');
    app(SecretVault::class)->revokeGrant($secret->id, 'agent-client-1', null);

    // Grant again — the same (secret, client) pair is reactivated in place.
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    $lease = $this->leaseVaultSecret($secret->id, 'agent-client-1');
    expect($lease->secret)->toBe('sk-live-x');
});
