---
title: Pipes
description: Threat model for connected third-party accounts — sealed tokens in the vault, PKCE and state on the connect flow, deny-by-default leases, single-flight refresh
weight: 15
---

# Security: Pipes

A pipe connection holds a person's working credential for another company's system —
their GitHub repositories, their mailbox, their CRM. A leak hands an attacker that
person's access there, not just here. This page states what protects it.

## Controls

| Control | Mechanism | Where |
|---|---|---|
| Tokens sealed at rest | access and refresh tokens are **user-owned token-vault secrets** (SecretBox, AEAD-bound to the row) — never a column on the connection | `Support\PipeSecrets`, `TokenVault` |
| Client secret sealed | `pipes.client_secret_encrypted`, bound to the pipe id, registered for `cbox-id:crypto:rewrap`, hidden from `toArray()` | `Models\Pipe` |
| Every read of a token is a vault lease | the broker client `cbox-id:pipes` holds the only vault grant on each secret; refresh, revoke and an app's lease each lease through the vault with a purpose | `vault.secret.leased` on the audit trail |
| Deny-by-default for apps | an app needs a `PipeGrant` on the pipe; no grant, no pipe or a disabled pipe is one uniform `PipeLeaseDenied` | `DatabasePipeTokens::lease()` |
| CSRF on the connect flow | 128-bit `state`, compared in constant time; the host keeps it in the person's session | `PipeConnectState::matches()` |
| Code interception | PKCE S256 on every authorization request; the verifier never leaves the session | `PipeOAuthClient` |
| Account binding | the connection is written for the person and pipe recorded at `start()`, never for what the callback says | `DatabasePipeConnections::complete()` |
| Single-flight refresh | an atomic claim on `refresh_claimed_until`, so a rotating refresh token is never spent twice | `DatabasePipeTokens` |
| SSRF | every provider call is DNS-pinned and refuses private ranges (`pipes.verify_url`); parameters substituted into endpoints match strict patterns | `PipeOAuthClient`, `PipeParameter` |
| Tenancy | pipes, grants and connections are environment-owned; a person's own paths filter by user id, so another person's connection answers like a missing one | `BelongsToEnvironment` |
| Erasure | the vault's erasure step deletes the person's tokens; `pipes.connections` deletes their connections | `Erasure\PipeConnectionsErasureStep` |
| No secret in logs or audit | provider error bodies are reduced to the error code; audit context carries provider, scopes, client id and purpose — never a token or the client secret; nothing in the module logs | `PipeTokenRejected` |

## Honest limits

- **A leased token is the app's to protect.** Once leased it lives in the app's process and
  travels to the provider; the platform cannot claw it back. `leaseExpiresAt` is advisory.
  Revoking the app's grant stops future leases, not one in flight.
- **Not every provider can revoke.** Microsoft has no revocation endpoint. A disconnect
  forgets the tokens here; the person removes the app's consent at the provider.
- **Removing a pipe, and erasing a person, do not call the provider.** Both are local: the
  tokens are revoked or deleted in the vault, so nothing here can present them, but the
  provider's grant stays until it expires or is removed there. Disconnect first when it
  matters.
- **An authorised app can lease for any connected person in the environment.** The grant
  is per pipe, not per person. Whether an app owned by one organization should only lease
  for that organization's members is the host's policy to enforce before calling `lease()`.
- **Assumed lifetimes are assumptions.** Salesforce sends no `expires_in`; two hours is the
  default session policy, and an org with a shorter one will see the occasional refresh
  only after a failed API call.

## Auditing

`pipe.configured`, `pipe.updated`, `pipe.removed`, `pipe.grant.created`,
`pipe.grant.revoked`, `pipe.connection.connected`, `pipe.connection.failed`,
`pipe.connection.refreshed`, `pipe.connection.refresh_failed`,
`pipe.connection.needs_reauth`, `pipe.connection.disconnected`, `pipe.token.leased` and
`pipe.lease.denied` — plus the vault's own `vault.secret.*` and `vault.grant.*` entries
for the underlying secrets.
