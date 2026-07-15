---
title: SIEM audit streaming
description: Mirror the hash-chained, environment-scoped audit trail out to a customer's SIEM — isolation, at-least-once, dedup by chain hash
weight: 8
---

# SIEM audit streaming

Compliance teams want the platform's audit trail in *their* SIEM — Splunk, Elastic,
Graylog, an ArcSight/CEF collector — not just in the platform's database. The
`src/AuditStreaming/` module is the thin binding that pushes every recorded audit
entry OUT to a customer's SIEM, while preserving the two properties that make the
trail trustworthy: **tamper-evidence** (the hash chain) and **environment
isolation** (the hard outer boundary).

It does almost no work of its own. The heavy lifting is provided by two dependencies
this package requires and uses:

- **[`cboxdk/siem`](https://github.com/cboxdk/siem)** — the framework-agnostic core:
  the normalized `SiemEvent` value object and the formatters (Splunk HEC, Elastic
  ECS, ArcSight/syslog CEF, GELF, generic JSON) that turn it into what each SIEM
  ingests.
- **[`cboxdk/laravel-siem`](https://github.com/cboxdk/laravel-siem)** — the delivery
  engine: a transactional outbox, queued batched delivery with retry / backoff /
  dead-letter / circuit-breaker, SSRF-guarded HTTP egress, encrypted destination
  secrets, and PII redaction.

This module composes those two into the platform's environment model. Everything
below is what *this* package adds on top.

## The mental model

```
 audit entry (hash-chained)                         customer SIEM
        │                                                 ▲
        ▼                                                 │
  StreamingAuditLog ──► outbox row (transactional) ──► pump ──► HTTP sink
   (records + maps        env-owned, commits with        env-owned, delivers
    to a SiemEvent)       the entry atomically           inside its environment
```

1. **Record.** `StreamingAuditLog` decorates the framework
   [`AuditLog`](../security/_index.md). When an entry is recorded, it maps the
   `AuditEntry` to a `SiemEvent` and writes one outbox row per configured stream —
   in the **same database transaction** as the entry itself.
2. **Pump.** A scheduled job drains each stream's outbox off the request thread,
   formats the events for that destination, and ships them over the SSRF-guarded
   HTTP sink.

### The hash chain gives you two things for free

Each audit entry carries a `sequence`, a `prev_hash`, and its own content `hash`
(`hash = SHA256(canonical(entry) ‖ prev_hash)`). The mapper copies all three into
every `SiemEvent` it emits, and uses the entry **hash as the event id**. So the
receiving SIEM gets:

- **A dedup / idempotency key.** Delivery is *at-least-once* (see below), so the
  same event can arrive twice. Because its id is the content hash, the SIEM
  deduplicates trivially — two copies are byte-identical and collapse to one.
- **Tamper- and gap-evidence at the destination.** With `sequence` and `prev_hash`
  present, the customer can re-verify chain continuity in their own SIEM: a missing
  `sequence`, a broken `prev_hash` link, or a reordered event is detectable there,
  not only in the platform database. The chain is tamper-*evident*, not
  tamper-*proof* (an attacker who rewrites the whole trail could recompute it) — but
  streaming it to an independent system the platform operator does not control raises
  that bar considerably.

## Isolation is inherited, not re-implemented

An [environment](environments.md) is the platform's hard outer boundary. Audit
streaming does **not** add its own tenancy checks; it makes the SIEM engine's own
models environment-owned, so the always-on
[environment scope](environments.md) constrains every path automatically:

- `Models\AuditStream` and `Models\AuditStreamDelivery` subclass the engine's
  `LogStream` / `StreamDelivery` and add `BelongsToEnvironment`. Pointing
  `config('siem.models.*')` at them means the registry, the dispatcher, and the pump
  all query env-owned models — deny-by-default, so a query with no ambient
  environment matches **zero** rows.
- At **dispatch**, `StreamingAuditLog` runs inside the recording request's
  environment. Listing streams and writing outbox rows are therefore constrained to
  that environment: an env-A audit entry can only ever match and write env-A streams.
- At **pump**, the worker has no ambient environment. `Jobs\PumpAuditStream`
  reconstructs it explicitly: a provisioning-only `withoutScope` read learns the
  stream's `environment_id`, then `runAs` re-enters that exact environment before the
  engine's delivery runs — so the pump loads only that environment's rows and is
  structurally unable to touch another's.

The guarantee: **a stream registered in environment B never receives an environment
A event**, at both stages. This is enforced by the schema and the scope, not by a
`where` clause someone has to remember.

## Honest scope: at-least-once and unordered

- **At-least-once, not exactly-once.** The outbox row commits atomically with the
  audit entry (a rolled-back caller leaves neither), and the pump retries failures
  with bounded backoff. A destination can still receive a duplicate after a partial
  failure — dedup on the event id (the entry hash).
- **Per-stream ordering is best-effort, not guaranteed.** Batching, retries, and
  circuit-breaker cooldowns can reorder delivery relative to `sequence`. The
  `sequence` and `prev_hash` fields are exactly what let the receiver *detect* that
  and re-order or gap-check on their side.
- **Delivery coverage ≠ audit coverage.** Streaming mirrors what was recorded; it
  does not decide *what* gets recorded. Logging coverage is a separate obligation.

## What this module adds

| Piece | Responsibility |
| --- | --- |
| `StreamingAuditLog` | Decorates `AuditLog`; maps entry → `SiemEvent`; writes the outbox transactionally. Composes with a host decorator (e.g. impersonation attribution) — a stamped `context.impersonated_by` flows to the SIEM automatically. |
| `Models\AuditStream`, `Models\AuditStreamDelivery` | Environment-owned subclasses of the engine's models — the isolation seam. |
| `Contracts\SiemEventMapper` + `DefaultSiemEventMapper` | The `AuditEntry` → `SiemEvent` mapping. Rebind to refine category/outcome/severity for your action vocabulary. |
| `Jobs\PumpAuditStream` | Per-stream pump that reconstructs the environment (`withoutScope` → `runAs`). `ShouldBeUnique` per stream. |
| `Console\PumpAuditStreamsCommand` | The one cross-environment step: enumerate all enabled streams and dispatch a pump each. It dispatches; it never delivers. |

The delivery engine's own configuration (batching, retry, circuit breaker,
backpressure, HTTP egress) lives under the `siem.*` namespace published by
`cboxdk/laravel-siem`. This module forces three keys and owns none of the rest:
`siem.models.log_stream`, `siem.models.stream_delivery`, and
`siem.schedule.enabled = false` (the platform owns scheduling, so the pump can
reconstruct each stream's environment).

See the [cookbook recipe](../cookbook/enable-an-audit-stream.md) to enable a stream,
and the [security note](../security/audit-streaming.md) for the operator-only
controls.
