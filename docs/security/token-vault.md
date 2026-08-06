---
title: Token vault
description: Threat model and sealing rationale for the AI token vault — sealed-at-rest, deny-by-default leases, uniform denial, audited access
weight: 14
---

# Security: token vault

The token vault (`Cbox\Id\TokenVault\`) holds third-party credentials that grant
real downstream power, so its controls are load-bearing. This page states the
threat model, the sealing choice, and the honest limits.

## What the vault protects, and how

| Control | Mechanism | Where |
| --- | --- | --- |
| Sealed at rest | `SecretBox` (XChaCha20-Poly1305) ciphertext, AEAD-bound to the row id; never a plaintext or a hash | `DatabaseSecretVault`, `VaultSecret::secretContext()` |
| Deny-by-default | ambient environment required; a lease needs a live `(secret, client)` grant | `DatabaseSecretVault::lease()`, `Models\VaultGrant` |
| Uniform denial | unknown / no-grant / revoked / expired all raise the same `LeaseDenied`; reason audited only | `Exceptions\LeaseDenied` |
| Revocable | revoked secret or grant, or expired secret, refuses on the next lease | `DatabaseSecretVault` |
| Accountable | store / rotate / revoke / grant / lease audited with actor + purpose, never the value | hash-chained audit trail |
| Environment scope | `BelongsToEnvironment` — cross-env access impossible | `Models\VaultSecret`, `Models\VaultGrant` |

## Why sealed, not hashed

A platform-issued token (a password-reset token, an OTP) is stored as a **hash**:
the platform only ever needs to *verify* a presented value, never reproduce it. A
vaulted downstream credential is the opposite — the vault must **present** the API
key to OpenAI or GitHub, so it must be **recoverable**. Hashing would make it
useless. So the value is **sealed** with the Crypto kernel's `SecretBox`: an
XChaCha20-Poly1305 AEAD envelope whose master key lives in config / a secret store,
not the database. A database dump therefore yields nothing without the master key,
and because the ciphertext is AEAD-bound (`cbox-id:vault-secret:<id>`) to its own
row, a dumped blob cannot be replayed against a different secret or column.

All primitives are vetted libsodium; nothing is hand-rolled.

## No enumeration on the lease path

Management operations (`rotate`, `revoke`, `grant`) throw `SecretNotFound` for a
missing secret — they are called by the trusted operator managing the vault. The
`lease()` path is different: it may be driven on behalf of a partially-trusted
agent, so every failure mode — the secret does not exist, the client has no grant,
the secret or grant is revoked, the secret has expired — raises the **same**
`LeaseDenied`. The precise reason is written to the audit trail
(`vault.lease.denied`), never returned, so a caller cannot probe which secret ids
exist.

## Honest limits

- **Lease TTL is advisory.** The vault returns the plaintext to an in-process caller
  with a window (`SecretLease::expiresAt`); it trusts the caller to stop using and
  drop the value by then. It is not a server-side, revocable token — revocation
  bounds future leases, not one in flight. Keep leases short; prefer downstream
  credentials that are themselves short-lived and narrowly scoped.
- **Post-lease exposure is out of scope.** Once leased, the value lives in the
  agent's memory and travels to the provider; the vault cannot protect it there.
- **No automatic master-key rotation.** The crypto kernel rotates asymmetric
  *signing* keys, not the symmetric `SecretBox` master key, and the sealed format
  carries no key-id prefix. Rotating the master key means re-sealing every entry
  yourself: open with the old-key box, seal with the new-key box, under the same
  row-bound context. The `key_version` column exists to make that migration
  auditable; treat a master-key change as a deliberate, scripted operation.
- **This is a primitive, not a policy.** Whether a given agent should hold a given
  credential, and for how long, is the host's decision; the vault enforces the
  mechanics — sealing, grants, uniform denial, audit.

## Auditing

`vault.secret.stored`, `vault.secret.rotated`, `vault.secret.revoked`,
`vault.grant.created`, `vault.grant.revoked`, `vault.secret.leased` and
`vault.lease.denied` are recorded on the hash-chained trail — with the acting
client, the target secret and the stated purpose, and **never** the secret value.
See [core-concepts/audit-streaming.md](../core-concepts/audit-streaming.md).
