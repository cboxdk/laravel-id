---
title: External actions
description: Threat model for inline hooks — per-point fail policy, signed + SSRF-guarded egress, reserved-claim protection, no-trace veto
weight: 17
---

# Security: external actions

Inline hooks let external logic influence security decisions (what a token contains,
whether it is issued), and they make outbound calls to customer endpoints — two things
that must be hardened. This page states the threat model.

## Controls

| Control | Mechanism | Where |
| --- | --- | --- |
| Per-point fail policy | a hook that throws / times out / errors → DENY at every gate; ALLOW at `post_login` and the notify-only points | `FailPolicy::for()`, `HttpActionTransport::onFailure()`, `DefaultActionPipeline::runInProcess()` |
| No credential material on the wire | password hooks carry the subject id only — never plaintext, hash or derivative | `PasswordChangePayload` |
| No veto a call site can misread | a deny at a `post_*` point is audited and folded to an allow, centrally | `DefaultActionPipeline::denied()`, `HookPoint::vetoable()` |
| Deny-by-default registration | only config-listed `Action` classes run; a non-Action entry is dropped | `ConfigActionRegistry` |
| No-trace veto | a veto throws `ActionDenied` BEFORE the `jti` row, the session row, the user row or the credential write | `JwtTokenIssuer::issue()`, `DatabaseSessionManager::start()`, `DatabaseSubjects::create()` / `setPassword()` |
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

## Why the gates fail closed — and why the login hook does not

A hook that can veto is a control. If the platform proceeded anyway when the hook was
unreachable, an attacker who could take the hook endpoint offline would strip the control —
so at every **gate** (`token_minting`, `pre_registration`, `pre_password_change`) the default
is to **deny**. This costs availability, which is the correct trade for a gate on a write
that is hard to undo, and the blast radius is bounded: a failed grant is retried, and
registrations and password changes are low-volume and user-initiated.

`post_login` is the exception, and deliberately so. Failing closed on the login path means
one customer-controlled URL going down locks *every* user of that tenant out of *every*
application — including the admin console they would use to pause the hook. That is a
self-inflicted, hard-to-recover outage in exchange for a control that only bites during the
outage; some logins going unexamined is the lesser harm. An operator who disagrees — a
regulated tenant that would rather block than admit an unexamined login — sets
`external_actions.fail_policy.post_login => 'closed'` and takes the availability risk
knowingly.

The `post_*` notification points fail open because there is nothing to fail closed to: the
operation has already committed.

Note what is NOT configurable: a hook that is consulted and answers **deny** always denies,
at every point. Fail policy only decides what silence means.

## Honest limits

- **Trust the endpoint you register.** A hook you point at a malicious URL can deny all your
  tokens or (within the non-reserved keyspace) add misleading claims. Registration is an
  operator action, SSRF-guarded, but the endpoint's *behaviour* is the operator's trust
  decision.
- **The receiver must verify the signature and timestamp.** The platform signs every request
  (`X-Cbox-Signature`) with the reveal-once secret; a receiver that doesn't check it accepts
  spoofed calls. The timestamp is in the signed material for replay rejection.
- **Latency is real.** The calls sit on the token and login paths; a slow endpoint slows
  every token and every login. Keep it fast and idempotent. A fan-out goes out concurrently,
  so the pipeline costs one endpoint's timeout rather than one per endpoint — but that also
  means an endpoint can be called for an operation another endpoint vetoed.
- **A `post_*` hook cannot undo anything.** It is a synchronous notification, not a
  transaction participant; if you need to refuse, refuse at the matching `pre_*` point.
- **Reserved claims are protected; everything else is trusted.** A hook can set any
  non-reserved claim, so treat hook-sourced claims as coming from the hook, not the platform.
