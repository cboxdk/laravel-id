---
title: Custom secret vault
description: Swap the storage and brokering behind the SecretVault contract — e.g. an HSM or an external secrets manager
weight: 40
---

# Custom secret vault

The [token vault](../core-concepts/token-vault.md) is bound contract-first, so you
can replace the default database-backed implementation without touching callers.

## The contract

`Cbox\Id\TokenVault\Contracts\SecretVault` is the whole seam:

```php
public function store(string $name, string $provider, string $secret, ?string $ownerType = null, ?string $ownerId = null, ?DateTimeInterface $expiresAt = null): VaultSecret;
public function rotate(string $secretId, string $newSecret): VaultSecret;
public function revoke(string $secretId): void;
public function grant(string $secretId, string $clientId, ?int $maxTtlSeconds = null): VaultGrant;
public function revokeGrant(string $secretId, string $clientId): void;
public function lease(string $secretId, string $clientId, string $purpose): SecretLease;
```

The default `DatabaseSecretVault` seals values with the Crypto kernel's `SecretBox`
and stores them in `vault_secrets` / `vault_grants`. Swap it when you want the
credential to live somewhere else — an HSM, AWS Secrets Manager, HashiCorp Vault —
while keeping the same deny-by-default grant model and audit contract.

## Bind your implementation

```php
use Cbox\Id\TokenVault\Contracts\SecretVault;

$this->app->singleton(SecretVault::class, MyHsmBackedVault::class);
```

## What your implementation MUST preserve

These are the guarantees callers rely on — not optional:

- **Deny-by-default.** `lease()` returns a value only when a live grant exists for the
  exact `(secret, client)` pair and the secret is neither revoked nor expired.
- **Uniform denial.** Every lease failure raises `LeaseDenied` (not a distinguishing
  error), so the vault is never an enumeration oracle. Management ops may throw
  `SecretNotFound`.
- **Audited, value-free.** Record store / rotate / revoke / grant / lease on the audit
  trail with the actor and purpose — and **never** the secret value.
- **Never persist the plaintext recoverably outside your sealed store.** If you keep it
  server-side, seal it (recoverable), never a plain hash — the vault must replay it.

## Test against the contract

Dogfood `Cbox\Id\TokenVault\Testing\InteractsWithTokenVault` and the shipped
`FakeTokenVault` mirror the deny-by-default semantics — write your implementation's
tests against the same behaviours (grant required, revoked/expired refused, uniform
`LeaseDenied`).

See [Security: token vault](../security/token-vault.md) for the full threat model.
