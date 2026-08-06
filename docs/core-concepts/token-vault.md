---
title: AI token vault
description: Seal downstream third-party credentials and broker short-lived, deny-by-default leased access to autonomous / AI agents
weight: 11
---

# AI token vault

The token vault (`Cbox\Id\TokenVault\`) holds the **downstream** credentials an
autonomous or AI agent must present to the services it calls — an OpenAI or
Anthropic API key, a GitHub or Google OAuth token — and hands them to the agent
only through a **short-lived, audited, deny-by-default lease**. The agent never
holds the long-lived secret; the vault does, sealed.

It is a server-side primitive (a contract you resolve and call), not an HTTP
endpoint and not a UI. It composes with [CIBA](ciba.md): a high-risk lease can be
gated behind a fresh human approval.

## Mental model

Two environment-owned records and one broker, all behind a contract:

- **`Models\VaultSecret`** — a downstream credential, stored SEALED via the Crypto
  kernel's `SecretBox` (XChaCha20-Poly1305, bound to the row). Because the vault
  must *replay* the value to the provider, it is sealed (recoverable), never merely
  hashed.
- **`Models\VaultGrant`** — the authorization edge: this agent (an OAuth `client_id`)
  may lease this secret. No live grant ⇒ no lease.
- **`Contracts\SecretVault`** (`DatabaseSecretVault`) — the broker: `store`,
  `rotate`, `revoke`, `grant`, `revokeGrant`, and `lease`.

```php
$vault = app(SecretVault::class);

// Ingest a downstream credential (sealed at rest).
$secret = $vault->store(name: 'openai-prod', provider: 'openai', secret: $apiKey);

// Authorize one agent client to use it, capping how long it may hold a lease.
$vault->grant($secret->id, clientId: 'agent-7', maxTtlSeconds: 60);

// The agent, when it needs to call OpenAI, leases the value for immediate use.
$lease = $vault->lease($secret->id, clientId: 'agent-7', purpose: 'summarize-ticket');
$response = $http->withToken($lease->secret)->post('https://api.openai.com/…');
// $lease->expiresAt is the advisory window; drop the value by then.
```

`lease()` returns a `ValueObjects\SecretLease` carrying the plaintext **in memory
only** — it is never persisted unsealed, logged, or written to an audit row.

## The security guarantees

- **Sealed at rest.** Only a `SecretBox` ciphertext is stored, bound (AEAD) to the
  secret's own row id, so a database dump reveals nothing without the master key and
  a blob cannot be replayed against another row.
- **Deny-by-default.** Every operation requires an ambient environment; a `lease()`
  is refused unless a live grant exists for the exact `(secret, client)` pair and
  the secret is neither revoked nor expired.
- **No enumeration oracle.** Every lease failure — unknown secret, no grant, revoked,
  expired — raises the *same* `LeaseDenied`; the real reason is audited, not returned.
- **Revocable.** Revoking a secret or a grant takes effect on the next lease.
- **Accountable.** Store / rotate / revoke / grant / lease are all recorded on the
  hash-chained audit trail with the acting client and the stated purpose — never the
  value.
- **Environment-owned.** A secret in one environment is invisible to any other.

## Honest scope

- **A lease TTL is advisory, not enforced.** The vault hands the plaintext to a
  trusted in-process caller and trusts it to stop using — and drop — the value by
  `expiresAt`. The lease is not a server-side token, so revocation bounds *future*
  leases, not one already in flight. For hard expiry, keep leases short and rotate.
- **The vault is only as safe as the caller.** Once leased, the plaintext lives in
  the agent's process; the vault cannot protect it there. Grant narrowly, cap TTLs,
  and prefer provider tokens that are themselves short-lived and scoped.
- **Master-key rotation is manual.** The crypto kernel does not rotate the SecretBox
  master key; the `key_version` column records which generation sealed each blob so a
  re-seal migration is auditable. See [Security: token vault](../security/token-vault.md).

## Where to go next

- [Vault a downstream credential](../cookbook/vault-a-downstream-credential.md) — the
  store → grant → lease recipe end to end.
- [Custom secret vault](../extension-points/custom-secret-vault.md) — swap the
  storage/broker behind the contract (e.g. an HSM or an external secrets manager).
- [CIBA backchannel approval](ciba.md) — gate a high-risk lease on a human's approval.
- [Security: token vault](../security/token-vault.md) — the threat model and the
  sealing rationale.
