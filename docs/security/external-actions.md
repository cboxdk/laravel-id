---
title: External actions
description: Threat model for inline hooks — fail-closed, signed + SSRF-guarded egress, reserved-claim protection, no-trace veto
weight: 17
---

# Security: external actions

Inline hooks let external logic influence security decisions (what a token contains,
whether it is issued), and they make outbound calls to customer endpoints — two things
that must be hardened. This page states the threat model.

## Controls

| Control | Mechanism | Where |
| --- | --- | --- |
| Fail-closed | a hook that throws / times out / errors → DENY (unless `fail_open`) | `HttpActionTransport::onFailure()`, `DefaultActionPipeline::runInProcess()` |
| Deny-by-default registration | only config-listed `Action` classes run; a non-Action entry is dropped | `ConfigActionRegistry` |
| No-trace veto | a veto throws `ActionDenied` BEFORE the `jti` row is written | `JwtTokenIssuer::issue()` |
| Reserved-claim protection | a hook can never overwrite `iss`/`sub`/`exp`/`scope`/`aud`/`cnf`/`ent`/… | `JwtTokenIssuer::applyEnrichment()` |
| SSRF-guarded egress | URL asserted at registration, IP-pinned per send, redirects off (same guard as webhooks) | `DatabaseExternalActions`, `HttpActionTransport`, `cboxdk/laravel-ssrf` |
| Signed request | HMAC-SHA256 over `"{ts}.{body}"`, `X-Cbox-Signature: t=..,v1=..` | `HttpActionTransport` |
| Sealed secret | reveal-once 256-bit secret, sealed at rest (SecretBox, row-bound) | `DatabaseExternalActions::register()` |
| Environment scope | endpoints are `BelongsToEnvironment` — cross-env invisible | `Models\ExternalActionEndpoint` |
| Audited veto | `external_action.denied` with the hook, deciding action and actors — never claim values | `DefaultActionPipeline::denied()` |

## Egress hardening (why it mirrors webhooks)

An external hook is authenticated, server-side egress carrying identity context — the same
SSRF surface as webhooks, so it reuses the exact guard: the URL is asserted at registration,
and every send resolves DNS, checks **all** returned IPs against private/reserved/cloud-
metadata ranges, pins the connection to the validated IP (defeating DNS-rebinding/TOCTOU),
and disables redirects (a 30x to an internal host is a fresh SSRF vector). TLS verification is
left ON. The one difference from webhooks is that a hook is **synchronous**: a short hard
timeout, **no retry**, and any failure is a deny rather than a scheduled retry.

## Why fail-closed

A hook that can enrich or veto a token is a control. If the platform issued the token anyway
when the hook was unreachable, an attacker who could take the hook endpoint offline would
strip the control — so the default is to **deny**. This costs availability (a downed hook
endpoint stops token issuance), which is the correct trade for a security gate. The
`fail_open` switch exists for enrichment-only hooks where the enrichment is a nicety, not a
gate, and the operator knowingly accepts issuing without it.

## Honest limits

- **Trust the endpoint you register.** A hook you point at a malicious URL can deny all your
  tokens or (within the non-reserved keyspace) add misleading claims. Registration is an
  operator action, SSRF-guarded, but the endpoint's *behaviour* is the operator's trust
  decision.
- **The receiver must verify the signature and timestamp.** The platform signs every request
  (`X-Cbox-Signature`) with the reveal-once secret; a receiver that doesn't check it accepts
  spoofed calls. The timestamp is in the signed material for replay rejection.
- **Latency is real.** The call is on the token path; a slow endpoint slows every token. Keep
  it fast and idempotent.
- **Reserved claims are protected; everything else is trusted.** A hook can set any
  non-reserved claim, so treat hook-sourced claims as coming from the hook, not the platform.
