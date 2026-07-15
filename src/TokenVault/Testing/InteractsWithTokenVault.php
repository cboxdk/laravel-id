<?php

declare(strict_types=1);

namespace Cbox\Id\TokenVault\Testing;

use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Models\VaultGrant;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\TokenVault\ValueObjects\SecretLease;

/**
 * Drop-in test ergonomics for the token vault, shipped with the package so
 * downstream consumers get the same fluency:
 *
 *     use Cbox\Id\TokenVault\Testing\InteractsWithTokenVault;
 *
 *     uses(InteractsWithTokenVault::class);
 *
 *     it('leases a granted secret to an agent', function () {
 *         $secret = $this->storeVaultSecret('openai', 'openai', 'sk-live-…');
 *         $this->grantVaultAccess($secret->id, 'agent-client-1');
 *         $lease = $this->leaseVaultSecret($secret->id, 'agent-client-1', 'summarize');
 *         expect($lease->secret)->toBe('sk-live-…');
 *     });
 */
trait InteractsWithTokenVault
{
    protected function storeVaultSecret(
        string $name,
        string $provider,
        string $secret,
        ?string $ownerType = null,
        ?string $ownerId = null,
    ): VaultSecret {
        return app(SecretVault::class)->store($name, $provider, $secret, $ownerType, $ownerId);
    }

    protected function grantVaultAccess(string $secretId, string $clientId, ?int $maxTtlSeconds = null): VaultGrant
    {
        return app(SecretVault::class)->grant($secretId, $clientId, $maxTtlSeconds);
    }

    protected function leaseVaultSecret(string $secretId, string $clientId, string $purpose = 'test'): SecretLease
    {
        return app(SecretVault::class)->lease($secretId, $clientId, $purpose);
    }
}
