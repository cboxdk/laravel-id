<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Usage\Testing\InteractsWithUsage;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\TokenVault\Testing\FakeTokenVault;
use Cbox\Id\TokenVault\Testing\InteractsWithTokenVault;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use PHPUnit\Framework\ExpectationFailedException;

uses(RefreshDatabase::class);

/**
 * {@see FakeTokenVault} ships to consumers but had no exercise of its own — an
 * unexercised fake is worse than no fake, because a host app writes its whole suite
 * against behaviour nobody checks. These tests drive it exactly as a consumer does:
 * bound as the SecretVault, then used through the shipped
 * {@see InteractsWithTokenVault} helpers.
 *
 * NOTE for maintainers: unlike {@see InteractsWithUsage},
 * the vault trait offers no `fakeVault()` entry point, so every consumer has to know
 * to write the `app()->instance(...)` line below themselves.
 */
beforeEach(function (): void {
    $this->fake = new FakeTokenVault;
    app()->instance(SecretVault::class, $this->fake);
});

it('stores, grants and leases through the shipped trait helpers', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-abc123');
    $this->grantVaultAccess($secret->id, 'agent-client-1');

    $lease = $this->leaseVaultSecret($secret->id, 'agent-client-1', 'summarize');

    expect($lease->secret)->toBe('sk-live-abc123')
        ->and($lease->secretId)->toBe($secret->id)
        ->and($lease->provider)->toBe('openai')
        ->and($lease->expiresAt->getTimestamp())->toBeGreaterThan(time());
});

it('keeps everything in memory — no vault row is ever persisted', function (): void {
    // The point of the fake: a host app's suite gets vault behaviour without the
    // package's tables, and plaintext never reaches a database.
    $secret = $this->storeVaultSecret('stripe', 'stripe', 'sk_test_x');
    $this->grantVaultAccess($secret->id, 'client-1');
    $this->leaseVaultSecret($secret->id, 'client-1');

    expect(VaultSecret::query()->count())->toBe(0);
});

it('is deny-by-default: leasing without a grant is refused', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-abc123');

    expect(fn () => $this->leaseVaultSecret($secret->id, 'unauthorized-client'))
        ->toThrow(LeaseDenied::class);

    $this->fake->assertNothingLeased();
});

it('refuses a lease for a revoked secret, and for an expired one', function (): void {
    $revoked = $this->storeVaultSecret('openai', 'openai', 'sk-1');
    $this->grantVaultAccess($revoked->id, 'client-1');
    app(SecretVault::class)->revoke($revoked->id);

    expect(fn () => $this->leaseVaultSecret($revoked->id, 'client-1'))->toThrow(LeaseDenied::class);

    $expired = app(SecretVault::class)->store('old', 'openai', 'sk-2', null, now()->subDay());
    app(SecretVault::class)->grant($expired->id, 'client-1');

    expect(fn () => $this->leaseVaultSecret($expired->id, 'client-1'))->toThrow(LeaseDenied::class);

    // A uniform LeaseDenied for every refusal — no oracle telling a caller WHICH of
    // "no such secret", "no grant" or "revoked" applied.
    expect(fn () => $this->leaseVaultSecret('does-not-exist', 'client-1'))->toThrow(LeaseDenied::class);

    $this->fake->assertNothingLeased();
});

it('stops leasing once the grant is revoked', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-abc123');
    $this->grantVaultAccess($secret->id, 'client-1');
    $this->leaseVaultSecret($secret->id, 'client-1');

    app(SecretVault::class)->revokeGrant($secret->id, 'client-1');

    expect(fn () => $this->leaseVaultSecret($secret->id, 'client-1'))->toThrow(LeaseDenied::class);
    $this->fake->assertLeaseCount(1);
});

it('serves the rotated plaintext after a rotation', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-old');
    $this->grantVaultAccess($secret->id, 'client-1');

    app(SecretVault::class)->rotate($secret->id, 'sk-new');

    expect($this->leaseVaultSecret($secret->id, 'client-1')->secret)->toBe('sk-new');
});

it('caps the lease TTL at the grant maximum', function (): void {
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live');
    $this->grantVaultAccess($secret->id, 'client-1', maxTtlSeconds: 30);

    $lease = $this->leaseVaultSecret($secret->id, 'client-1');

    expect($lease->expiresAt->getTimestamp())->toBeLessThanOrEqual(time() + 30);
});

it('reports an unknown secret id on the mutate paths', function (): void {
    expect(fn () => app(SecretVault::class)->rotate('nope', 'x'))->toThrow(SecretNotFound::class)
        ->and(fn () => app(SecretVault::class)->revoke('nope'))->toThrow(SecretNotFound::class)
        ->and(fn () => app(SecretVault::class)->grant('nope', 'client-1'))->toThrow(SecretNotFound::class);
});

it('records ownership on a stored secret', function (): void {
    $owner = VaultOwner::organization('org_a');
    $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live', $owner);

    expect($secret->owner_type)->toBe($owner->type->value)
        ->and($secret->owner_id)->toBe('org_a');
});

it('drives its assertion helpers off the leases it actually recorded', function (): void {
    $first = $this->storeVaultSecret('a', 'openai', 'sk-a');
    $second = $this->storeVaultSecret('b', 'openai', 'sk-b');
    $this->grantVaultAccess($first->id, 'client-1');
    $this->grantVaultAccess($second->id, 'client-1');

    $this->leaseVaultSecret($first->id, 'client-1', 'summarize');
    $this->leaseVaultSecret($first->id, 'client-1', 'translate');

    $this->fake->assertLeased($first->id);
    $this->fake->assertLeaseCount(2);

    // The helper is a real assertion, not a rubber stamp: a secret that was never
    // leased must fail it.
    expect(fn () => $this->fake->assertLeased($second->id))
        ->toThrow(ExpectationFailedException::class);

    expect($this->fake->leases[0]['purpose'])->toBe('summarize')
        ->and($this->fake->leases[1]['purpose'])->toBe('translate');
});
