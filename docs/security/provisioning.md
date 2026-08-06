---
title: Outbound provisioning security
description: SSRF-guarded egress, encrypted secrets, TLS, deny-by-default scope, and honest at-least-once delivery
weight: 12
---

# Outbound provisioning security

Outbound provisioning makes authenticated, server-side HTTP calls to
operator-configured URLs carrying an organization's user data. Its controls mirror
the platform's other egress paths (webhooks, federation, SIEM streaming).

## SSRF-guarded egress

Every outbound URL — a connection's SCIM base URL **and** an OAuth token URL — is
validated by the shared, independently-tested `cboxdk/laravel-ssrf` guard before a
request is made:

- **At registration**, `SafeScimUrl::assert()` rejects a base URL that resolves to
  a loopback, private, link-local or reserved address (e.g. the cloud-metadata
  endpoint `169.254.169.254`), so an unsafe target is never stored.
- **At delivery**, the connection is **pinned** to the exact IPs resolved by the
  guard immediately before connecting (`pinnedOptions`), and redirects are refused
  (`withoutRedirecting`). A DNS rebind between check and connect, or a 30x toward an
  internal host, cannot redirect the request — the TOCTOU window is closed.

`config('cbox-id.provisioning.verify_url')` (default `true`) is **operator-only**.
Never expose it to a tenant/org admin: a tenant that could disable the guard could
point a connection at an internal address. A single-tenant/on-prem install
delivering to an internal SCIM endpoint may set it false.

## TLS

Delivery runs over the platform HTTP client with certificate verification on; the
guard's pinning does not disable TLS verification. There is no per-connection toggle
to turn it off.

## Secrets at rest (reveal-once)

A connection's bearer token / OAuth client secret is sealed with the Crypto
`SecretBox` (XChaCha20-Poly1305 AEAD), bound as additional authenticated data to
that connection's id — a ciphertext sealed for one connection cannot be opened
against another. The raw secret is:

- never stored in plaintext (only the sealed column `auth_secret_encrypted`);
- never returned again after registration (there is no reveal endpoint);
- opened only at delivery time to build the `Authorization` header;
- never written into an operation's `last_error` or a dead-letter row — a failed
  response is reduced to its status and SCIM `detail`, and the header is never
  logged.

## Deny-by-default isolation

`ProvisioningConnection`, `ProvisionedResource` and `ProvisioningOperation` are
environment-owned. The hard environment scope is deny-by-default (no ambient
environment ⇒ zero rows), so:

- with **no connection** in an environment, a change enqueues nothing and makes no
  outbound call;
- a connection in env-A can only ever be enqueued against, and delivered from,
  within env-A — proven by cross-environment tests at both the dispatch and drain
  stages;
- the drain job, running in a worker with no ambient environment, reconstructs the
  connection's environment (`withoutScope` single-id read → `runAs`) rather than
  trusting one.

## Resilience limits

- **Bounded retries.** Transient failures (transport error, 429, 5xx) retry with
  exponential backoff + jitter up to `max_attempts`, then dead-letter
  (`exhausted`). A permanent 4xx is dead-lettered immediately — it will not
  self-correct.
- **Per-connection circuit breaker.** After `failure_threshold` consecutive
  transient failures a connection's breaker opens for `cooldown_seconds`; a failing
  downstream app pauses only itself and never blocks another connection.

## Honest scope: at-least-once

Delivery is **at-least-once**. The transactional outbox and per-connection
`ShouldBeUnique` drain keep the normal case to a single delivery, and SCIM PATCH
`replace` operations are idempotent, so a redelivery converges. It is **not**
exactly-once: a downstream app that acknowledges after a network cut may see a
repeat. Receivers should key on `externalId`. We do not claim delivery guarantees
we cannot keep, nor SCIM conformance beyond what the tests exercise (RFC 7643/7644
payload shapes against an in-memory server and the real HTTP client).
