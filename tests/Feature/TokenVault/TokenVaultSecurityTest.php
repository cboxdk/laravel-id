<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('seals the credential at rest — the row never holds the plaintext', function (): void {
    $plaintext = 'sk-live-super-secret-value';
    $secret = $this->storeVaultSecret('openai', 'openai', $plaintext);

    $stored = VaultSecret::query()->whereKey($secret->id)->firstOrFail();

    // The at-rest column is a SecretBox ciphertext, not the value (and it is not a
    // mere hash — it can be opened back to the original, which the vault needs).
    expect($stored->secret_encrypted)->not->toBe($plaintext)
        ->and($stored->secret_encrypted)->not->toContain($plaintext)
        ->and(app(SecretBox::class)->open($stored->secret_encrypted, $stored->secretContext()))->toBe($plaintext);
});

it('binds the ciphertext to its own row (AEAD context) — it cannot be opened against another', function (): void {
    $a = $this->storeVaultSecret('a', 'openai', 'value-a');
    $b = $this->storeVaultSecret('b', 'openai', 'value-b');

    $stored = VaultSecret::query()->whereKey($a->id)->firstOrFail();

    // Opening A's blob under B's context fails — a dumped row cannot be replayed
    // against a different secret.
    expect(fn () => app(SecretBox::class)->open($stored->secret_encrypted, $b->secretContext()))
        ->toThrow(DecryptionFailed::class);
});

it('never puts the secret value in an audit row', function (): void {
    $audit = $this->fakeAudit();
    $plaintext = 'sk-live-audit-canary';

    $secret = $this->storeVaultSecret('openai', 'openai', $plaintext);
    $this->grantVaultAccess($secret->id, 'agent-client-1');
    $this->leaseVaultSecret($secret->id, 'agent-client-1', 'canary-check');

    $audit->assertRecorded('vault.secret.stored');
    $audit->assertRecorded('vault.secret.leased');

    // No recorded event carries the plaintext anywhere in its context.
    foreach ($audit->recorded as $event) {
        expect(json_encode($event->context))->not->toContain($plaintext);
    }
});

it('audits a denied lease with its reason but not the value', function (): void {
    $audit = $this->fakeAudit();

    // No grant → denied; the denial is still accounted for.
    expect(fn () => $this->leaseVaultSecret('01VAULTNONEXISTENT000000000', 'agent-client-1'))
        ->toThrow(LeaseDenied::class);

    $audit->assertRecorded('vault.lease.denied');
});
